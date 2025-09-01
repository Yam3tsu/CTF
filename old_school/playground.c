#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/random.h>

#define AVAILABLE_SLOTS 32
#define MAX_CHUNK_SIZE 0x68

#define INVALID_SIZE(idx) (malloc_usable_size(chunks[idx].allocated_chunk) != chunks[idx].allocated_size || chunks[idx].requested_size > chunks[idx].allocated_size)

typedef struct {
    void *allocated_chunk;

    size_t allocated:1;
    size_t allocated_size:31;
    size_t requested_size:32;
} __attribute__((packed)) chunk_t;

chunk_t *alloc_chunk_list() {
    chunk_t *chunks = NULL;

    if (getrandom(&chunks, 4, 0) == -1) {
        perror("getrandom");
        exit(EXIT_FAILURE);
    }

    chunks = mmap((void *) ((uintptr_t) chunks << 12), AVAILABLE_SLOTS * sizeof(chunk_t), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);

    if (chunks == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    return chunks;
}

__attribute__((constructor))
void init() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
}

void panic(char *msg) {
    size_t msg_len = 0;
    while (msg[msg_len]) msg_len++;

    write(1, msg, msg_len);
    write(1, "\n", 1);
    _exit(EXIT_FAILURE);
}

void menu() {
    puts("==========");
    puts("a > alloc");
    puts("p > print");
    puts("r > resize");
    puts("e > edit");
    puts("f > free");
    puts("q > quit");
    puts("==========");
    printf("> ");
}

size_t get_uint(const char *prompt) {
    size_t value = -1;
    printf("%s", prompt);
    scanf(" %zu%*c", &value);
    return value;
}

void chunk_alloc(chunk_t *chunks) {
    size_t size = get_uint("size > ");

    if (size > MAX_CHUNK_SIZE) {
        puts("invalid size");
        return;
    }

    for (size_t i = 0; i < AVAILABLE_SLOTS; i++) {
        if (!chunks[i].allocated) {
            chunks[i].requested_size = size;

            chunks[i].allocated_chunk = malloc(chunks[i].requested_size);

            if (chunks[i].allocated_chunk == NULL) {
                puts("allocation failed");
                return;
            }

            chunks[i].allocated_size = malloc_usable_size(chunks[i].allocated_chunk);
            chunks[i].allocated = 1;

            puts("ok");
            return;
        }
    }

    puts("full");
}

void chunk_print(chunk_t *chunks) {
    size_t index = get_uint("index > ") % AVAILABLE_SLOTS;

    if (!chunks[index].allocated) {
        puts("invalid index");
        return;
    }

    puts("==========");
    puts(chunks[index].allocated_chunk);
    puts("==========");
}

void chunk_edit(chunk_t *chunks) {
    size_t index = get_uint("index > ") % AVAILABLE_SLOTS;

    if (!chunks[index].allocated) {
        puts("invalid index");
        return;
    }

    if (INVALID_SIZE(index)) {
        panic("invalid chunk size detected");
    }

    printf("data > ");
    char *chunk = (char *) chunks[index].allocated_chunk;
    size_t size = chunks[index].requested_size;

    fgets(chunk, size, stdin);
    
    puts("ok");
}

void chunk_free(chunk_t *chunks) {
    size_t index = get_uint("index > ") % AVAILABLE_SLOTS;

    if (!chunks[index].allocated) {
        puts("invalid index");
        return;
    }

    if (INVALID_SIZE(index)) {
        panic("invalid chunk size detected");
    }

    free(chunks[index].allocated_chunk);
    chunks[index].allocated = 0;

    puts("ok");
}

void chunk_resize(chunk_t *chunks) {
    size_t index = get_uint("index > ") % AVAILABLE_SLOTS;

    if (!chunks[index].allocated) {
        puts("invalid index");
        return;
    }

    if (INVALID_SIZE(index)) {
        panic("invalid chunk size detected");
    }

    size_t new_size = get_uint("new size > ");

    if (new_size > MAX_CHUNK_SIZE) {
        puts("invalid size");
        return;
    }

    chunks[index].requested_size = new_size;

    void *new_chunk = realloc(chunks[index].allocated_chunk, chunks[index].requested_size);

    if (new_chunk == NULL) {
        puts("reallocation failed");
        return;
    }

    chunks[index].allocated_chunk = new_chunk;
    chunks[index].allocated_size = malloc_usable_size(chunks[index].allocated_chunk);

    puts("ok");
}

int main() {
    
    size_t choice = ' ';
    chunk_t *chunks = alloc_chunk_list();

    do {
        menu();

        scanf(" %c%*c", &choice);

        switch (choice) {
            case 'a':
                chunk_alloc(chunks);
                break;
            case 'p':
                chunk_print(chunks);
                break;
            case 'e':
                chunk_edit(chunks);
                break;
            case 'f':
                chunk_free(chunks);
                break;
            case 'r':
                chunk_resize(chunks);
                break;
            case 'q':
                puts("bye");
                break;
            default:
                puts("invalid choice");
                break;
        }

    } while (choice != 'q');

    return 0;
}