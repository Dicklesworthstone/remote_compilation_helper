/**
 * RCH E2E Test Fixture - C Hello World
 *
 * Implementation of the hello library functions.
 */

#include "hello.h"

const char* get_greeting(void) {
    return "Hello from rch test fixture!";
}

int add(int a, int b) {
    return a + b;
}

int multiply(int a, int b) {
    return a * b;
}
