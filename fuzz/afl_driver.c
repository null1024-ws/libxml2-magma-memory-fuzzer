#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

extern int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

int main(int argc, char** argv) {
    const size_t MAX_BUF_SIZE = 1048576; // 1MB


    uint8_t* buf = (uint8_t*)malloc(MAX_BUF_SIZE);
    if (!buf) {
        fprintf(stderr, "Failed to allocate memory.\n");
        return EXIT_FAILURE;
    }


    // while (__AFL_LOOP(10)) {
    int loop_count=1;
    while (--loop_count) {

        ssize_t len = read(STDIN_FILENO, buf, MAX_BUF_SIZE);
        if (len > 0) {

            LLVMFuzzerTestOneInput(buf, (size_t)len);
        }
    }

    free(buf);

    return EXIT_SUCCESS;
}
