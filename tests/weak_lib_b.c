/*
 * Test fixture: a second shared library that exports wa_target as a strong,
 * default, unversioned definition. Paired with a first library that also
 * defines wa_target, it provides the "strong definition exists elsewhere" that
 * got-audit's Alert 2 (d) reasons about.
 */
int wa_target(void) { return 2; }
