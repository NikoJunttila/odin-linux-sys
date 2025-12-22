#include <stdio.h>
#include <unistd.h>

static __attribute__((constructor)) void init_method(void) {
  printf("injected\n");
}
