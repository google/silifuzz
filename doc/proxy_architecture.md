# SiliFuzz proxy architecture

This document describes the desirable state of proxy/filtering/making
configuration. We are optimizing for:

*   Configuration simplicity and reproducibility across different proxies.
*   Number of memory mappings that will be created at runtime. Fewer is better.

### Fuzzing

##### Memory mappings

Establish a single executable page inside the following virtual address range

1.  `[0x30000000; 0xB0000000)` (*CODE*)

Establish read/write 2 data mappings 0.5Gb each in different parts of the
address space.

1.  `[0x10000, 0x20010000)` (*DATA1*)
1.  `[0x1000010000, 0x1020010000)` (*DATA2*)

Two desirable properties that these mappings should satisfy are:

*   a single instruction, e.g. a bit set, can translate an address from one
    mapping to an address of another mapping
*   one mapping resides in the lower 2Gb and the other does not

The combined size of all *CODE* and *DATA* mappings must stay below 3Gb to limit
per-runner memory footprint. The actual upper limit is machine specific and
depends on the RAM/CPU ratio.

NOTE: In reality runners share a lot of pages with the orchestrator and
therefore the limit is higher but we are being conservative.

During fuzzing, the proxy will create the *DATA* mappings with the corresponding
prot bits and place a single page in the *CODE* range at the address based on
the content hash of the instruction sequence.

This setup guarantees each input can only read and execute a single page of code
and read/write anywhere inside the *DATA* regions during fuzzing.

##### Initial register state

Ideally, we want the initial state to be as simple as possible which is
everything set to 0. In practice this is not possible for a variety of platform
and proxy-specific reasons.

The program counter (`PC`) and the stack pointer (`SP`) registers must always be
initialized accordingly. The `PC` is always set to the first byte of the
instruction sequence (`CODE_PAGE_start`). The stack pointer is always set to
`DATA1_limit`.

All other registers must be consistently initialized across fuzzing and the
subsequent filtering/making stages of the pipeline.

NOTE: On X86_64 at least the following registers must be non-zero: `%cs`, `%ss`
and `%xmm0`. The two segment selectors are set by the kernel to 0x33 and 0x2b
for userspace. The xmm register is a workaround for
[erratum 1386](https://www.amd.com/system/files/TechDocs/56683-PUB-1.07.pdf)

TODO(ncbray): Document AArch64 requirements.

To help the fuzzing engine reach better coverage faster we can pre-seed the
dictionary with instructions to initialize GP registers. For example, we can add
sequences like `mov DATA1_start, %rax` and similar to help discover writable
memory pages.

##### Expected end state

For any input instruction sequence with size X the expected PC value is
`CODE_PAGE_start+X`. Expected register and memory states are undefined.

### Filtering and making

At the filter phase (which is executed on the target hardware during fuzzing)
the code will be similarly placed inside the *CODE* region but no *DATA*
mappings will be created initially. Instead, the filter will perform snapshot
expansion (i.e. map new pages) as needed with the added restriction that all
reads/writes must happen inside the *DATA* regions. The result of this process
is a corpus of snapshots that can only access the predefined *CODE* and *DATA*
address ranges.

The make stage will be similarly augmented to ensure all memory accesses are
inside the predefined regions.

### Running

To minimize the number of memory mappings created by each runner we can pre-map
the *CODE* mapping as a single mapping. Similarly, we can coalesce adjacent
mappings inside the *DATA* regions and map them in a single `mmap()` call. These
measures can dramatically reduce the number of memory mappings each runner
creates from O(snapshots_per_shard) to O(1).

On the downside, this optimization makes large contiguous chunks of memory
accessible to every snapshot and potentially reduces the runner’s ability to
detect SDCs (e.g. detecting accesses to memory outside of the declared
mappings). To reduce the chances of this we can poke holes in the *CODE* and
*DATA* regions with `PROT_NONE` pages until we reach some predefined maximum
number of mappings.
