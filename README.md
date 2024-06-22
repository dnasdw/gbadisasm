# gbatools

## Platforms

- Windows (XP or later)
- Linux (x86_64)
- macOS (x86_64, arm64)

## Building

### Dependencies

- cmake

### Windows

```Shell
MD build
PUSHD build
cmake [-T v141_xp] [-A Win32]|[-A x64]|[-A ARM64] ..
cmake --build . --target install --config Release --clean-first
POPD
```

### Linux

```Shell
mkdir build
pushd build
cmake [-DCMAKE_BUILD_TYPE=Release]|[-DCMAKE_BUILD_TYPE=Debug] [-DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain/aarch64-linux-gnu.toolchain.cmake] ..
cmake --build . --target install --clean-first
popd
```

### macOS

```Shell
mkdir build
pushd build
cmake [-DCMAKE_BUILD_TYPE=Release]|[-DCMAKE_BUILD_TYPE=Debug] [-DCMAKE_OSX_ARCHITECTURES=x86_64]|[-DCMAKE_OSX_ARCHITECTURES=arm64]|["-DCMAKE_OSX_ARCHITECTURES=x86_64;arm64"] [-DCMAKE_OSX_DEPLOYMENT_TARGET=10.6]|[-DCMAKE_OSX_DEPLOYMENT_TARGET=11.0] ..
cmake --build . --target install --clean-first
popd
```
