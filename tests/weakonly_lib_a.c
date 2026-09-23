/*
 * Test fixture (positive control for Alert 2 (d)): the resolved library exports
 * wa_target as a *weak* definition with no strong symbol at its address. Loaded
 * ahead of weak_lib_b.c it wins the binding (first-in-scope), so the GOT slot
 * resolves to a weak definition while a strong one exists elsewhere -- exactly
 * the anomaly Alert 2 (d) must report.
 */
__attribute__((weak)) int wa_target(void) { return 1; }
