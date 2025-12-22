#### procfs mem  

To write our payload to a remote process using procfs, we simply need to write it to the mem file at the correct offset. Any change that is made to the mem file is applied to the process memory. To perform these operations, we can use the normal file APIs (Snippet 4).

  `// Open the process mem file   FILE *file = fopen("/proc/<pid>/mem", "w");    // Set the file index to our required offset, representing the memory address   fseek(file, address, SEEK_SET);    // Write our payload to the mem file   fwrite(payload, sizeof(char), payload_size, file);`




`gdb` uses `/proc/<pid>/mem` to access memory, and `pread()` / `pwrite()` to read and edit it


**Important note about ptrace permissions:** On modern Linux systems, you may also need to either:

- Run with `sudo` (if tracing a process you don't own)
- Adjust ptrace scope: `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` (allows any process of the same user to trace each other)

https://www.labs.greynoise.io/grimoire/2025-01-28-process-injection/?referrer=grok.com

https://blog.xpnsec.com/linux-process-injection-aka-injecting-into-sshd-for-fun/

https://blog.hackingforce.com.br/en/linux-process-injection?referrer=grok.com

https://github.com/farinap5/linux-injection/tree/main

Perhaps, disabling ASLR would make the process simpler, turning off address randomization. `echo 0 > /proc/sys/kernel/randomize_va_space`
