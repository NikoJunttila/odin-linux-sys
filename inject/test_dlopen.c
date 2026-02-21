#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>

int main() {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    printf("dlopen addr: %p\n", dlopen);
    printf("libc %p\n", handle);
    
    FILE *f = fopen("/proc/self/maps", "r");
    char line[256];
    while(fgets(line, sizeof(line), f)) {
        if(strstr(line, "libc.so") || strstr(line, "libdl.so")) {
            printf("%s", line);
        }
    }
    return 0;
}
