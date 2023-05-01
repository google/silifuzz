
### What is a SiliFuzz test

A test is a sequence of bytes that can be executed by the target hardware. The
expected result for each test is obtained from a pool of presumed healthy
devices. The expected result can vary between microarchitectures.

SiliFuzz provides a specialized execution environment and infrastructure to
prepare and run billions of tests at high speed, and assess success/failure of
individual tests.

### SiliFuzz execution environment

SiliFuzz provides the following execution environment for the tests:

*   The test code is mapped at page-aligned address.
*   Prior to executing each test, the registers are set to their default values
    (0 for most GP and FP registers, PC points to start of the code, SP points
    to the end of a writable page, flag registers are initialized to well-known
    defaults e.g. 0x202 for EFLAGS).
*   Only certain well-known (**TBD**) memory address ranges can be read from and
    written to. These are all zero-initialized.
*   A special *trampoline* (sometimes called the exit sequence) is appended to
    every test. The trampoline transfers control back to SiliFuzz runtime.
*   The runtime limits the amount of CPU time that each test can consume.
*   (currently) executes as a Linux user-space process.

### What makes a good SiliFuzz test

A test is a sequence of instructions represented as raw bytes.

At most 4000 bytes of code executing up to 100000 dynamic instructions. These
limits are flexible and can be ignored given a strong reason.

The test **must** execute deterministically. Currently, the test **should not**
cause an exception and **should** reach the *trampoline*.

Examples of non-deterministic behaviors that must be avoided are:

*   directly accessing the value of the PC (program counter) register. The test
    code must be position-independent
*   system calls *or* instructions that trap into the kernel
*   random number generations
*   `CPUID`-like instructions
*   reading timestamp/perf counters (e.g. `RDTSC`)
*   reading from/writing to MSR (deterministic MSR may be ok to read from
    assuming these are accessible)
*   executing instruction that behave differently across kernel
    versions/configurations (`WRFSBASE`, `SGDT`, etc on x86_64 or reading from
    `id_aa64mmfr0_el1` on AArch64)
*   executing privileged instructions
*   reading from/writing and jumping to memory addresses outside of the
    well-known addresses.

Other soft limits on test content:

*   should not execute instructions that can affect other tenants on the machine
    ([splitlocks](https://lwn.net/Articles/790464/) on x86_64, WFE on AArch64).
*   a single test generally should not access more than X (X < 5) memory pages
*   tests should not read from the code page
*   a single test should generally consume less than 1ms of CPU time

The SiliFuzz runtime and content-preparation infrastructure implements measures
to prevent many types of unwanted behavior but it's not bullet-proof.
