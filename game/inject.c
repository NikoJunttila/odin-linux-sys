#include <stdio.h>
#include <unistd.h>

// This function runs automatically when the .so is loaded into a process
__attribute__((constructor))
void on_load(void) {
    printf("[INJECTED] Library loaded into PID: %d\n", getpid());
    
    // You can add your payload here
    // For example: modify memory, hook functions, etc.
}

// This function runs when the .so is unloaded
__attribute__((destructor))
void on_unload(void) {
    printf("[INJECTED] Library unloading from PID: %d\n", getpid());
}

// Export a function that can be called after injection
void do_something(void) {
    printf("[INJECTED] do_something() called!\n");
}
