#include <cstdio>
int main() {
    char buf[4096];
    __builtin_memset(buf, 'A', sizeof(buf));
    for(;;) fwrite(buf, 1, sizeof(buf), stdout);
}
