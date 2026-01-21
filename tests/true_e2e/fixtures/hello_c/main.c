/**
 * RCH E2E Test Fixture - C Hello World
 *
 * Main program that uses the hello library.
 */

#include <stdio.h>
#include "hello.h"

int main(void) {
    printf("%s\n", get_greeting());
    printf("2 + 2 = %d\n", add(2, 2));
    printf("3 * 4 = %d\n", multiply(3, 4));
    return 0;
}
