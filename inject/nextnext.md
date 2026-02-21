you'll eventually want to find the "Base Address" of the game process using procfs_find_memory_region(pid, "r-xp", "game") just like we did with libc, and then add a fixed offset to it. But for now,
