#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE (1024 * 1024)

typedef struct Node {
    char *block;
    struct Node *next;
} Node;

int main() {
    Node *head = NULL;

    while (1) {
        Node *node = (Node *)malloc(sizeof(Node));
        node->block = (char *)malloc(BLOCK_SIZE);
        memset(node->block, 0x5A, BLOCK_SIZE);
        node->next = head;
        head = node;
    }

    return 0;
}
