/*
 * Test fixture: links against two shared libraries that both export the same
 * strong, default, unversioned symbol, calls it through the PLT (so a GOT jump
 * slot exists for it), then pauses so got-audit can attach. got-audit's Alert 1
 * must report the symbol as resolvable from more than one library -- unless the
 * name is on got-audit's allowlist, in which case Alert 1 stays silent.
 *
 * The symbol name is configurable via -DDUP_SYM and must match the one used for
 * the libraries.
 */
#include <unistd.h>
#include <stdio.h>

#ifndef DUP_SYM
#define DUP_SYM shared_target
#endif

int DUP_SYM(void);

int main(void) {
    volatile int r = DUP_SYM();
    printf("dup result=%d\n", r);
    fflush(stdout);
    pause();
    return 0;
}
