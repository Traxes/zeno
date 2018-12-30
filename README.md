# AVD

currently a bad name... but naming is hard!

# TODO

- Beauty Code
    - Prefix internal Methods with _

- Core
    - Slicing
    - Arch Support
    
- Reporter
    - include into Plugin System

- GUI

- Extern Interface in DLLs

- Plugins
    - BufferOverflow
    - Out of Bounds
    - IntegerOverflow
    - Format String
    - Uninitialized Memory
        - Graph Slicing!
        
# False Positive
- CWE457_Use_of_Uninitialized_Variable__char_pointer_17_bad()
    - False positive on goodG2B

# DONE

- Plugin loader

# Resources & Similar Projects

- https://github.com/cetfor/PaperMachete


Buffer Overflows:
gets <- always
char buf[123]; std::cin>>buf 
