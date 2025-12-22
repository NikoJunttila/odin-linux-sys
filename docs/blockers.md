
Linux mechanisms that make it possible:

- `/proc/<pid>/mem`
    
- `ptrace`
    
- `/proc/<pid>/maps` (to locate regions)
    

### ❌ Things that can block you

- **Yama ptrace restrictions**
    
- **Proton/Wine sandboxing**
    
- **Game integrity / anti-cheat**
    
- **ASLR** (addresses change every run)
    
- **Wine address translation**
