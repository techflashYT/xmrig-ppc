# XMRig-PPC

This is a fork of [XMRig](https://github.com/xmrig/xmrig) that is attempting to add support for running on the PowerPC platform.

## Current status
- Good stuff
  - XMRig builds targetting PPC, and runs on real, and emulated, PPC hardware
  - Implemented CPU vendor and model detection based on lscpu_arm.cpp
  - Set `APP_ARCH` for PPC targets to handle the "built for \[os\] \[arch\]" line on start
- Bad stuff
  - Trying to mine SAL with algo rx/0 results in a bunch of invalid shares.
  - Trying to mine XMR results in a seemingly infinite busy-hang waiting for dataset init

## Building

I use the following set of commands from an x86_64 machine.  You need to modify cmake-toolchain-ppc.txt to suit your environment.  Native builds are not yet tested.

```
mkdir build
cd build
cp ../cmake-toolchain-ppc.txt ./cmake-toolchain.txt
cmake .. -DWITH_TLS=OFF -DWITH_HWLOC=OFF -DWITH_GHOSTRIDER=OFF -DWITH_ARGON2=OFF -DWITH_RANDOMX=ON -DWITH_CN_LITE=OFF -DWITH_CN_HEAVY=OFF -DWITH_CN_PICO=OFF -DWITH_CN_FEMTO=OFF -DWITH_ASM=OFF -DWITH_VAES=OFF -DWITH_OPENCL=OFF -DWITH_CUDA=OFF -DBUILD_STATIC=ON -DCMAKE_TOOLCHAIN_FILE=cmake-toolchain.txt
```

## Dev Notes

- This probably doesn't build for x86.  Some gross hacks have been made to core code to get this to work.
- Comments starting with `TODO: plat-cleanup` are TODOs for when I eventually add a dedicated PPC platform, rather than just piggybacking off the x86 code.

