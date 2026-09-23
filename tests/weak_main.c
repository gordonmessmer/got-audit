/*
 * Test fixture: links against two shared libraries that both define wa_target,
 * calls it through the PLT (so a GOT jump slot exists for it), then pauses so
 * got-audit can attach. The first library (liba) is loaded ahead of the second
 * (libb) and wins the binding; whether Alert 2 (d) fires depends on whether
 * liba's winning definition is a bare weak symbol (positive control) or a weak
 * alias of a same-address strong symbol (negative control).
 */
#include <unistd.h>
#include <stdio.h>

int wa_target(void);

int main(void) {
    volatile int r = wa_target();
    printf("wa_target=%d\n", r);
    fflush(stdout);
    pause();
    return 0;
}
