#include <iostream>

void infiniteRecursion(int depth) {
    std::cout << "Depth: " << depth << std::endl;
    infiniteRecursion(depth + 1);
}

int main() {
    infiniteRecursion(0);
    return 0;
}
