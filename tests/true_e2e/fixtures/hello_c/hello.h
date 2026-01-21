/**
 * RCH E2E Test Fixture - C Hello World
 *
 * Header file for the hello library.
 */

#ifndef HELLO_H
#define HELLO_H

/**
 * Get a greeting message.
 *
 * @return A pointer to a static greeting string.
 */
const char* get_greeting(void);

/**
 * Add two integers.
 *
 * @param a First integer.
 * @param b Second integer.
 * @return The sum of a and b.
 */
int add(int a, int b);

/**
 * Multiply two integers.
 *
 * @param a First integer.
 * @param b Second integer.
 * @return The product of a and b.
 */
int multiply(int a, int b);

#endif /* HELLO_H */
