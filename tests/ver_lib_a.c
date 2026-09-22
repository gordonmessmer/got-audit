/*
 * Test fixture: one of two shared libraries that both export ver_target as a
 * strong, default, *versioned* symbol (ver_target@@MYVER_1.0, see ver.map). This
 * models an attacker exporting the very symbol it is stealing under the same
 * version node as the real owner; got-audit's Alert 1 must still report it.
 */
int ver_target(void) { return 1; }
