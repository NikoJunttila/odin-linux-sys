#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void onLoad() {
    printf("\n========= PAYLOAD LOADED =========\n");
    fflush(stdout);
}
