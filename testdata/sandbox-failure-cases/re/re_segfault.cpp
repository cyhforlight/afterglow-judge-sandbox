#include <iostream>

int main() {
    int* ptr = nullptr;
    *ptr = 42;
    std::cout << *ptr << std::endl;
    return 0;
}
