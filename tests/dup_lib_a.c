/*
 * Test fixture: one of two shared libraries that both export the same strong,
 * default, unversioned symbol. Loading both makes the resolution of the symbol
 * ambiguous, which got-audit's Alert 1 must report.
 *
 * The symbol name is configurable via -DDUP_SYM so the same fixture serves two
 * tests: the default (shared_target) is a name got-audit does not allowlist, so
 * Alert 1 fires; building with an allowlisted name instead proves the allowlist
 * suppresses Alert 1 for it.
 */
#ifndef DUP_SYM
#define DUP_SYM shared_target
#endif
int DUP_SYM(void) { return 1; }
