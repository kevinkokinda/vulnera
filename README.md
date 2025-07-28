# vulnera
# Spectre

## Requirements

*   C++ Compiler (GCC, Clang, etc.)
*   CMake (>= 3.14)
*   Go (>= 1.18)

## Build

```bash
# From project root
mkdir -p build && cd build
cmake -DCMAKE_INSTALL_PREFIX=./install ..
cmake --build . --target install
cd ../cli
go build -o spectre
```

## Run

**Terminal 1: Start Daemon**
```bash
# From project root
export LD_LIBRARY_PATH=$(pwd)/build/install/lib
export CANARY_WEBHOOK_API_URL="<your_webhook_url>"
./build/install/bin/spectre-d
```

**Terminal 2: Run Scan**
```bash
# From project root
./cli/spectre ssrf-scan "http://example.com/page?url=FUZZ"
```
BUILT FOR LEARNING - DO NOT USE MALICIOUSLY 
