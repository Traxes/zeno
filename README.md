# Zeno Framework

# Installation
```
cd ~
git clone https://github.com/Traxes/zeno --recursive
sudo pip3 install termcolor tqdm
git clone https://github.com/Z3Prover/z3 --recursive
cd z3
python3 scripts/mk_make.py --python
cd build
make
sudo make install
cd ~/zeno
```

# Usage
```
~/zeno$ PYTHONPATH=$PYTHONPATH:$HOME/zeno python3 src/main.py
```

# Example
For running all plugins on target.bin
```
~/zeno$ PYTHONPATH=$PYTHONPATH:$HOME/zeno python3 src/main.py target.bin
```


# Documentation

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
