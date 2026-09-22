/*
 * Test fixture: links against two shared libraries that both export the strong,
 * default, unversioned symbol shared_target, calls it through the PLT (so a GOT
 * jump slot exists for it), then pauses so got-audit can attach. got-audit's
 * Alert 1 must report shared_target as resolvable from more than one library.
 */
#include <unistd.h>
#include <stdio.h>

int shared_target(void);

int main(void) {
    volatile int r = shared_target();
    printf("shared_target=%d\n", r);
    fflush(stdout);
    pause();
    return 0;
}
