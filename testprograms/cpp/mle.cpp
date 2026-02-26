#include <cstdlib>
#include <cstring>
int main() {
    while(true) {
        char *p = (char*)malloc(1024*1024);
        if(!p) return 1;
        memset(p, 1, 1024*1024);
    }
}
