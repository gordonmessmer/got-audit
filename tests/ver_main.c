/*
 * Test fixture: links against two shared libraries that both export the strong,
 * default, versioned symbol ver_target@@MYVER_1.0, calls it through the PLT, then
 * pauses. The reference is versioned (ver_target@MYVER_1.0), so this exercises
 * the version-matching path of Alert 1: two strong candidates satisfy the
 * versioned reference and must be reported.
 */
#include <unistd.h>
#include <stdio.h>

int ver_target(void);

int main(void) {
    volatile int r = ver_target();
    printf("ver_target=%d\n", r);
    fflush(stdout);
    pause();
    return 0;
}
