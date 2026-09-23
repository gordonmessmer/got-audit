/*
 * Test fixture: the second of two shared libraries that both export the same
 * strong, default, unversioned symbol (see dup_lib_a.c). The symbol name is
 * configurable via -DDUP_SYM and must match the one used for dup_lib_a.c.
 */
#ifndef DUP_SYM
#define DUP_SYM shared_target
#endif
int DUP_SYM(void) { return 2; }
