#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/highmem.h>
#include <linux/mm.h>
 
MODULE_LICENSE("GPL");
 
unsigned long **syscall_table;
asmlinkage long (*original_sys_read)(unsigned int, char __user *, size_t);
 
// Find the syscall table address
unsigned long **find_syscall_table(void) {
    unsigned long int offset = PAGE_OFFSET;
    unsigned long **sct;
 
    while (offset < ULLONG_MAX) {
        sct = (unsigned long **)offset;
        if (sct[__NR_close] == (unsigned long *)sys_close)
            return sct;
        offset += sizeof(void *);
    }
    return NULL;
}
 
// Hooked syscall
asmlinkage long hooked_sys_read(unsigned int fd, char __user *buf, size_t count) {
    printk(KERN_INFO "Hooked sys_read called\n");
    return original_sys_read(fd, buf, count);
}
 
// Hide the module
static void hide_module(void) {
    list_del(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    printk(KERN_INFO "Module hidden\n");
}
 
// Read process memory
ssize_t read_process_memory(struct task_struct *task, unsigned long addr, void *buf, size_t len) {
    struct mm_struct *mm = task->mm;
    ssize_t read = 0;
    unsigned long page_addr;
    unsigned long offset;
    void *kaddr;
 
    down_read(&mm->mmap_sem);
    while (len) {
        page_addr = addr & PAGE_MASK;
        offset = addr & ~PAGE_MASK;
        kaddr = kmap(pfn_to_page(vmalloc_to_pfn((void *)page_addr)));
 
        if (!kaddr)
            break;
 
        read = copy_from_user(buf, kaddr + offset, len);
        kunmap(pfn_to_page(vmalloc_to_pfn((void *)page_addr)));
        if (read)
            break;
 
        len -= read;
        buf += read;
        addr += read;
    }
    up_read(&mm->mmap_sem);
 
    return read;
}
 
// Write process memory
ssize_t write_process_memory(struct task_struct *task, unsigned long addr, void *buf, size_t len) {
    struct mm_struct *mm = task->mm;
    ssize_t written = 0;
    unsigned long page_addr;
    unsigned long offset;
    void *kaddr;
 
    down_write(&mm->mmap_sem);
    while (len) {
        page_addr = addr & PAGE_MASK;
        offset = addr & ~PAGE_MASK;
        kaddr = kmap(pfn_to_page(vmalloc_to_pfn((void *)page_addr)));
 
        if (!kaddr)
            break;
 
        written = copy_to_user(kaddr + offset, buf, len);
        kunmap(pfn_to_page(vmalloc_to_pfn((void *)page_addr)));
        if (written)
            break;
 
        len -= written;
        buf += written;
        addr += written;
    }
    up_write(&mm->mmap_sem);
 
    return written;
}
 
// Helper function to get task_struct by process name
struct task_struct *get_task_by_name(const char *name) {
    struct task_struct *task;
    for_each_process(task) {
        if (strcmp(task->comm, name) == 0) {
            return task;
        }
    }
    return NULL;
}
 
// Entry point
static int __init onload(void) {
    const char *target_process_name = "cs2"; // Change this to the actual name of the process
    unsigned long target_address = 0xdeadbeef; // Change this to the target address in cs2
    char buffer[128]; // Buffer for reading/writing
    struct task_struct *task;
 
    syscall_table = find_syscall_table();
    if (!syscall_table)
        return -1;
 
    write_cr0(read_cr0() & (~0x10000));
    original_sys_read = (void *)syscall_table[__NR_read];
    syscall_table[__NR_read] = (unsigned long *)hooked_sys_read;
    write_cr0(read_cr0() | 0x10000);
 
    hide_module();
 
    task = get_task_by_name(target_process_name);
    if (!task) {
        printk(KERN_INFO "Process %s not found\n", target_process_name);
        return -1;
    }
 
    printk(KERN_INFO "Found process %s with PID %d\n", target_process_name, task->pid);
 
    // Example of reading process memory
    memset(buffer, 0, sizeof(buffer));
    read_process_memory(task, target_address, buffer, sizeof(buffer));
    printk(KERN_INFO "Read from process: %s\n", buffer);
 
    // Example of writing to process memory
    strcpy(buffer, "Hello from kernel");
    write_process_memory(task, target_address, buffer, sizeof(buffer));
    printk(KERN_INFO "Wrote to process memory\n");
 
    return 0;
}
 
static void __exit onunload(void) {
    if (!syscall_table)
        return;
 
    write_cr0(read_cr0() & (~0x10000));
    syscall_table[__NR_read] = (unsigned long *)original_sys_read;
    write_cr0(read_cr0() | 0x10000);
}
 
module_init(onload);
module_exit(onunload);
