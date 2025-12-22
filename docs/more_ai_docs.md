- You can inspect memory regions via `/proc/[PID]/maps` just like native Linux apps
### 📂 File descriptors & IO

|File|Use|
|---|---|
|`fd/`|All open file descriptors|
|`fdinfo/`|Extra info (offsets, flags)|
|`io`|Read/write statistics|

`ls -l /proc/11461/fd`

You can see:

- Open files
    
- Sockets
    
- Pipes
    
- Deleted files still in use

### 🧠 Memory internals (very powerful)

|File|Use|
|---|---|
|`maps`|Virtual memory regions|
|`smaps`|Detailed memory usage per region|
|`smaps_rollup`|Aggregated memory stats|
|`statm`|Fast memory summary|
|`numa_maps`|NUMA placement|
|`pagemap`|Virtual → physical mapping (root)|

`cat /proc/11461/smaps_rollup`

Shows:

- RSS
    
- PSS
    
- Shared/private memory
    
- Swap usage

readelf -h /proc/11461/exe
to get bit size

cat /proc/11461/status
basic info
