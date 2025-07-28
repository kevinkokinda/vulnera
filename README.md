# Spectre

## Requirements

*   C++ Compiler (GCC, Clang, etc.)
*   CMake (>= 3.14)
*   Go (>= 1.18)

## Build

```bash
# From project root
mkdir -p build && cd build
cmake ..
make -j$(nproc)
```

## Run

**Terminal 1: Start Daemon**
```bash
# From project root
mkdir -p all_plugins
find build/plugins -name "*.so" -exec cp {} all_plugins/ \;
LD_LIBRARY_PATH=./build/spectre-d:./build/_deps/cpr-build/cpr ./build/spectre-d/spectre-d all_plugins/
```

**Terminal 2: Run Attack**
```bash
# From cli directory
cd cli
go run . attack https://example.com
```

I'll apply this change now.
