/*
 * Test fixture: the second shared library exporting ver_target@@MYVER_1.0 as a
 * strong, default, versioned symbol (see ver_lib_a.c and ver.map).
 */
int ver_target(void) { return 2; }
