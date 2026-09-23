/*
 * Test fixture (negative control for Alert 2 (d)): the resolved library exports
 * a strong __wa_target and a *weak alias* wa_target at the same address -- the
 * ubiquitous glibc idiom (backtrace over __backtrace). Loaded ahead of
 * weak_lib_b.c the weak alias wins the binding, and weak_lib_b.c still exports a
 * strong wa_target elsewhere. Alert 2 (d) must NOT fire here: the weak symbol is
 * only an alias of a same-address strong symbol in the same object.
 */
int __wa_target(void) { return 1; }
extern __typeof(__wa_target) wa_target __attribute__((weak, alias("__wa_target")));
