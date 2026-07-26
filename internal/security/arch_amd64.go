package security

// AUDIT_ARCH_X86_64 from linux/audit.h: EM_X86_64 (62) with the 64-bit and
// little-endian bits set. seccomp compares seccomp_data.arch against this so a
// process cannot reach a blocked syscall by entering the kernel through a
// different ABI, where the same number means a different call.
const nativeArch = 0xc000003e
