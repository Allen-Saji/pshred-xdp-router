#![no_std]

// Library target so this crate can be a build-dependency of the userspace
// loader. The XDP program itself lives in the binary target (main.rs), built
// for the BPF target by aya-build.
