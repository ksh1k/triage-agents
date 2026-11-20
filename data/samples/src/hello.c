/* Benign test program #1: a plain "hello world".
 * Used as the "nothing suspicious here" baseline for the static-analysis tools.
 * It is only ever parsed by pefile, never executed by this project. */
#include <stdio.h>

int main(void) {
    printf("Hello from the Triage Agents test suite.\n");
    return 0;
}
