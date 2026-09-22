# How got-audit decides when to alert

## What we are defending against

got-audit exists to catch **function hijacking**: a shared library capturing a
symbol that legitimately belongs to another library, so that calls are silently
redirected to attacker-controlled code. The Global Offset Table (GOT) is where
that redirection becomes observable — each GOT slot holds the address the dynamic
loader chose for one imported function, and we can compare that choice against the
choice the loader *should* have made.

Two independent things can go wrong, so got-audit raises two independent kinds of
alert:

1. **Ambiguous resolution** — more than one library is a legitimate candidate for
   a reference, so *which* one wins depends on load order. Even if today's winner
   is benign, the ambiguity is a latent hijack: change the load order (an extra
   `LD_PRELOAD`, a new dependency) and the symbol moves.
2. **Illegitimate resolution** — the GOT slot points at a definition the loader's
   own rules would never have selected for this reference. That is either raw GOT
   patching or an interposer that the versioning rules should have excluded.

Both are computed from the same model of how the GNU loader resolves a symbol, so
the rest of this document describes that model first.

### The motivating attack: IFUNC-based GOT rewriting

The attack that motivated this tool (the xz-utils / liblzma backdoor,
CVE-2024-3094) abused a GNU indirect function (`STT_GNU_IFUNC`) not to *win*
symbol resolution but as an **execution opportunity**. An IFUNC's resolver is
ordinary code that the dynamic loader calls during relocation processing — early
in startup, while the GOT is still writable, before it is sealed by RELRO. The
backdoor's resolver ran during that window and **rewrote the process's GOT
directly**, repointing an unrelated symbol at attacker code. It did not export a
colliding symbol, and it did not rely on version or binding precedence; it simply
overwrote the pointer while it could.

This is the "illegitimate resolution" case, and it is exactly what **Alert 2**
exists for. got-audit reads the address actually stored in each GOT slot and
checks it against the library that address lands in. A slot overwritten to point
at code that does not legitimately provide that symbol for the reference fails the
export/version/binding check and is reported — regardless of how the pointer got
there. Because Alert 2 trusts only the observed pointer and never the resolver, an
IFUNC that rewrites the GOT is caught the same way any raw GOT patch is. (got-audit
separately reports each object's RELRO status, since a writable GOT is the
precondition this class of attack depends on.)

The xz backdoor did **not** export the symbol it stole — it simply pointed the GOT
at code the resolved library does not provide, which is what Alert 2 catches. But
the two alerts are designed to be **jointly inescapable**, so that closing this
one gap does not open another. An attacker who tries to make a hijack *look*
legitimate by **exporting the very symbol they are stealing** does not evade
detection:

- Export a **strong, matching** definition (same version node, or an unversioned
  wildcard) and your library becomes a *second* strong candidate for the
  reference alongside its real owner — which is exactly what **Alert 1** reports.
  For a strong, default symbol whose real owner always exports it (OpenSSL's
  `libcrypto`/`libssl` are the reference case), this is unavoidable.
- Export a definition that does **not** satisfy the reference — a mismatched
  version, or a non-default `@` node for an unversioned reference — and **Alert 2**
  reports it (cases (b)/(c) below).
- Export it only as a **weak** definition, to stay under Alert 1's strong-only
  count, and **Alert 2** reports it as a weak binding while a strong owner exists
  (case (d) below).

In other words, Alert 2 catches the "didn't export it" hijack and Alert 1 catches
the "exported it to blend in" hijack; there is no way to point a GOT slot at
attacker code and satisfy both. (The one residual case is a symbol that is *weak
everywhere*, with no strong owner to compare against — not the situation for the
strong, default symbols this tool is primarily protecting.)

## The resolution model (mirrors glibc `check_match`)

Every GOT reference carries a *version requirement*, taken from the referring
object's `.gnu.version` / `.gnu.version_r` sections — not from the symbol name.
A reference is one of:

- **versioned** — it needs a specific version node `V` (e.g. `GLIBC_2.2.5`), or
- **unversioned** — it names a bare symbol with no version requirement.

Every *definition* an object exports carries, from its `.gnu.version` /
`.gnu.version_d` sections:

- a **version node** (or none — an unversioned definition),
- a **default** flag (a `@@` default node or an unversioned symbol) versus a
  **non-default** node (a `@` hidden node, invisible to unversioned references),
  and
- a **binding**: **strong** (`STB_GLOBAL`) or **weak** (`STB_WEAK`).

A definition **can satisfy** a reference when:

| Reference | A definition satisfies it if… |
| --- | --- |
| versioned `S@V` | its version node is `V`, **or** it is an *unversioned* definition of `S` |
| unversioned `S` | it is a **default** definition of `S` (a `@@` node or unversioned) |

The unversioned-definition row is the crucial one for hijacking: an unversioned
export acts as a **wildcard** that can capture a versioned reference. This is the
`LD_PRELOAD` interposition path, and it is exactly how a malicious library steals
a symbol that another library defines with a specific version.

Among the definitions that *can* satisfy a reference, the loader prefers a
**strong** definition over a **weak** one regardless of load order; only among
equally-strong candidates does first-in-load-order win.

## Alert 1 — ambiguous resolution (the duplicate rule)

For each GOT reference, compute the set of libraries holding a **strong**
definition that **can satisfy** that reference (per the table above). If two or
more *distinct* libraries remain, the resolution is load-order-dependent and we
alert.

This replaces the old approach of comparing bare symbol names, which flagged any
name that appeared in two libraries even when versioning made the binding
deterministic. Because the rule is driven by each reference's own version
requirement, the common "false duplicates" disappear with no hard-coded list:

- Two libraries exporting the same name under **different default version nodes**
  (e.g. Samba's private libraries, or `xdr_*` in libc vs. libtirpc) are *not*
  ambiguous — a versioned reference matches exactly one of them.
- A definition that is only **weak** does not count toward the "two strong
  candidates" test, so weak compatibility aliases (`copysign`, `frexp`, `ldexp`,
  …) no longer trip the rule.

A reference defined both in the **main executable** and in exactly one library is
also not reported: an executable may legitimately provide its own copy of a
library symbol for its own use.

### Residual allowlist

A small number of genuinely-duplicated **strong** symbols remain ambiguous under
the rule above but are known-good; they live in `GotAuditor::expected_duplicates_`
in `src/got_auditor.cpp`, grouped and labelled by origin (libc/libm, libsasl2 and
its plugins, libresolv/libvncserver). The allowlist suppresses **Alert 1 only** —
it never suppresses Alert 2 — so an allowlisted symbol that is nonetheless
resolved to a definition the loader would not pick is still reported.

## Alert 2 — illegitimate resolution (the hijack detector)

Alert 1 asks "is the choice ambiguous?"; Alert 2 asks "was the *actual* choice
legal?". Using the address actually stored in the GOT slot, we identify the
library it resolves into and check that library's definition of the symbol against
the reference. It is load-order-independent and is **not** subject to the
allowlist. We alert when:

- **(a) not exported** — the resolved library does not define the symbol at all
  (the classic sign of a patched GOT slot pointing into the wrong object).
- **(b) version mismatch** — the reference is versioned `S@V`, but the resolved
  library provides neither `S@V` nor an unversioned `S`. The loader could not
  have produced this binding.
- **(c) non-default capture** — the reference is unversioned, but the resolved
  definition is a **non-default** (`@`, hidden) node. Unversioned references are
  invisible to hidden nodes, so the loader would never bind here.
- **(d) weak over strong** — the resolved definition is **weak**, yet another
  library holds a **strong** definition that can satisfy the reference. The loader
  prefers strong regardless of load order, so a weak binding while a strong one
  exists is anomalous. This closes the gap Alert 1 leaves open: a single GOT slot
  pointing at a weak/non-default definition in one library while the real strong
  owner sits elsewhere is a hijack that duplicate-counting alone would miss.

## Why two alerts instead of one

The two alerts cover the two ways a hijack manifests, and together they leave an
attacker no clean move (see the IFUNC discussion above):

- **Alert 2** answers "did the *actual* GOT binding go somewhere the loader's
  rules forbid?" — a raw GOT patch, an IFUNC that rewrote a slot, or a
  weak/non-default capture. This is the direct incident detector.
- **Alert 1** answers "does a symbol have more than one strong definition that
  could legitimately win?" — which is precisely what appears when an attacker
  *exports the symbol they are stealing* to make the binding look legal to Alert 2.
  A duplicate strong, default definition of a symbol another library already owns
  is not merely a "smell": for symbols like OpenSSL's, whose owner is unambiguous,
  it is the signature of an export-to-blend-in hijack, and it is reported.

The reference-driven candidate rule is what makes Alert 1 precise enough to be a
first-class signal rather than noise: because each reference's own version
requirement decides the candidate set, the benign cross-library name collisions
that a bare-name comparison would flag simply do not arise, leaving only the small
labelled allowlist. The allowlist quiets those known-good duplicates for Alert 1
without ever suppressing Alert 2, so an allowlisted symbol that is nonetheless
resolved somewhere illegitimate is still caught.
