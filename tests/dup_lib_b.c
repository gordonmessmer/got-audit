/*
 * Test fixture: the second of two shared libraries that both export the same
 * strong, default, unversioned symbol shared_target (see dup_lib_a.c).
 */
int shared_target(void) { return 2; }
