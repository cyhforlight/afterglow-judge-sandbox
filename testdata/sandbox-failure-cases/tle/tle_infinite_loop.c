#include <stdio.h>

int main() {
    long long sum = 0;
    for (;;) {
        sum += 1;
        sum *= 2;
        sum %= 1000000007;
    }
    return 0;
}
