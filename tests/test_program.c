/*
 * got-audit test program
 *
 * SPDX-License-Identifier: MIT
 *
 * Simple test program that loads several libraries.
 * Used to test got-audit functionality.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

volatile sig_atomic_t running = 1;

void signal_handler(int sig) {
    (void)sig;  /* Unused */
    running = 0;
}

int main(void) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("Test program PID: %d\n", getpid());
    printf("Press Ctrl+C to exit\n");
    fflush(stdout);

    /* Use some functions that will show up in GOT */
    char buffer[256];
    strcpy(buffer, "test");

    while (running) {
        sleep(1);
    }

    printf("Exiting\n");
    return 0;
}
