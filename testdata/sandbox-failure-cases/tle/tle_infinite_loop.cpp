#include <iostream>

int main() {
    long long sum = 0;
    while (true) {
        sum += 1;
        sum *= 3;
        sum %= 1000000007;
    }
    return 0;
}
