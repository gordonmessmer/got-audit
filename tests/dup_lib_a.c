/*
 * Test fixture: one of two shared libraries that both export the same strong,
 * default, unversioned symbol. Loading both makes the resolution of
 * shared_target ambiguous, which got-audit's Alert 1 must report.
 */
int shared_target(void) { return 1; }
