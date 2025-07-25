
# SiliFuzz - Fuzzing CPUs by proxy

## What is SiliFuzz

SiliFuzz is a system that finds CPU defects by fuzzing software proxies, like
CPU simulators or disassemblers, and then executing the accumulated test inputs
(known as the *corpus*) on actual CPUs on a large scale. SiliFuzz is a work in
progress, please refer to the
[paper](https://github.com/google/silifuzz/blob/master/paper/silifuzz.pdf) for
details.

## Terminology

##### Software fuzzing and coverage

Fuzzing is a technique of testing a target (an application, or an API) with a
large number of test inputs generated on the fly. The goal is to make these
inputs as interesting and as diverse as possible in order to trigger corner
cases. In other words, fuzzing aims to maximize the combined code coverage.
*Code coverage* may have different meanings, e.g. which basic blocks are
executed or which paths are taken in the program.

##### Proxy

For the purposes of SiliFuzz, a *proxy* is any software or hardware system that
behaves similar to some aspects of the target CPU. For example, a CPU emulator
or a disassembler. A proxy is needed when we cannot directly collect coverage
information from the target.

By applying fuzzing techniques to a proxy, we can generate a series of test
inputs (corpus) that produce interesting behavior in the proxy. Our underlying
assumption is that this translates into similarly interesting behavior in the
target. Read more in the [docs](https://github.com/google/silifuzz/blob/main/doc/proxy_architecture.md).

##### Corpus / Corpus shard

A collection of inputs used for testing the target is known as *corpus*.

A reasonably large corpus contains millions of inputs and is usually split into
multiple non-overlapping chunks called *shards*.

##### Snapshot

A SiliFuzz snapshot describes a short sequence of CPU instructions plus an
initial state of CPU registers and memory to deterministically execute that
sequence. A typical snapshot contains less than 100 bytes of code and runs in
microseconds, but it can be arbitrarily large. Snapshots are stored as
`silifuzz.proto.Snapshot` protocol buffers.

Snapshots are typically created from the inputs generated by a fuzzing engine.
For CPU testing purposes these inputs are filtered to eliminate all
non-deterministic snapshots. Read more in the
[docs](https://github.com/google/silifuzz/blob/main/doc/what_makes_a_good_test.md).

###### Expected end state

An end state describes the contents of registers and memory expected to exist at
the end of a Snapshot execution. If the snapshot executes differently on
different CPU microarchitectures it will have multiple expected end states.

##### Snap

A Snap is an in-memory representation of a **Snapshot** that can be easily
loaded and executed by the **Runner**. Snaps are typically loaded from disk by a
*reading runner*. The Snap on-disk format is essentially the same as the
in-memory one except that native pointers are replaced with offsets. See this
[header](https://github.com/google/silifuzz/blob/main/snap/gen/relocatable_snap_generator.h)
for details. This format is often referred to as *relocatable*. Each Snap
contains exactly one expected end state i.e. Snaps are
microarchitecture-specific. Read more in the [docs](https://github.com/google/silifuzz/blob/main/doc/snap.md).

##### Runner

Runner is a binary for testing a single CPU core. A runner consumes a corpus
shard, repeatedly executes random Snaps in it and checks that the expected end
state is reached. Runner is a single-threaded process.

##### Orchestrator

The orchestrator is a process that drives multiple runners. In a typical setting
the orchestrator will continuously execute one runner per logical CPU core, and
accumulate and report any failures produced by the individual runner processes.

## Supported platforms and microarchitectures

See [this file](https://github.com/google/silifuzz/blob/main/util/platform.h) for the
list of supported microarchitectures.

## Trophies

A non-exhaustive list of bugs and defects SiliFuzz has found.

### Bugs

A logic bug is an invalid CPU behavior inherent to a particular CPU
microarchitecture or stepping. SiliFuzz has identified the following bugs:

*   [CVE-2021-26339](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-1028.html)
*   [Erratum #1386](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/revision-guides/56323-PUB_1_01.pdf)
*   [Erratum #1468](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/revision-guides/56323-PUB_1_01.pdf)
*   [Erratum #3442699 for ARM Neoverse V2](https://developer.arm.com/documentation/SDEN-2332927/900)
*   [Erratum #3213672 for ARM Cortex-X3](https://developer.arm.com/documentation/SDEN-2055130/1400)

### Defects

An (electrical) defect is an invalid CPU behavior that happens only on one or
several chips. SiliFuzz has found the following defects we described in the
paper

*   F2XM1 Defect.
    [Paper](https://github.com/google/silifuzz/blob/master/paper/silifuzz.pdf) /
    Appendix A
*   Overshoot of an Illegal Instruction.
    [Paper](https://github.com/google/silifuzz/blob/master/paper/silifuzz.pdf) /
    Appendix B
*   FCOS Miscomputes.
    [Paper](https://github.com/google/silifuzz/blob/master/paper/silifuzz.pdf) /
    Appendix C
*   Missing x87 Data Pointer Update.
    [Paper](https://github.com/google/silifuzz/blob/master/paper/silifuzz.pdf) /
    Appendix D

## Related projects

*   [Centipede](https://github.com/google/fuzztest/blob/main/centipede/README.md)
    is a fuzzing engine developed at Google for fuzzing large and slow targets
    like CPU emulators.

## Prework

### Prework (for Bazel)

```shell
git clone https://github.com/google/silifuzz.git && cd silifuzz
SILIFUZZ_SRC_DIR=`pwd`
./install_build_dependencies.sh  # Currently, works for the latest Ubuntu only.
bazel build -c opt @silifuzz//tools:{snap_corpus_tool,fuzz_filter_tool,snap_tool,silifuzz_platform_id,simple_fix_tool_main} \
     @silifuzz//runner:reading_runner_main_nolibc \
     @silifuzz//orchestrator:silifuzz_orchestrator_main
SILIFUZZ_BIN_DIR=`pwd`/bazel-bin
cd "${SILIFUZZ_BIN_DIR}"
```

NOTE: You can use a Docker container to avoid polluting the host system: `docker
run -it --tty --security-opt seccomp=unconfined --mount
type=bind,source=${SILIFUZZ_SRC_DIR},target=/app ubuntu:noble /bin/bash -c
"cd /app && ./install_build_dependencies.sh && bazel build ... && bazel test
..."`

### Prework (fuzzing Unicorn target)

For Bazel, use the following commands.

```shell
cd "${SILIFUZZ_SRC_DIR}"
COV_FLAGS_FILE="$(bazel info output_base)/external/com_google_fuzztest/centipede/clang-flags.txt"
bazel build -c opt --copt=-UNDEBUG --dynamic_mode=off \
  --per_file_copt=unicorn/.*@$(xargs < "${COV_FLAGS_FILE}" |sed -e 's/,/\\,/g' -e 's/ /,/g') @//proxies:unicorn_x86_64
bazel build -c opt @com_google_fuzztest//centipede:centipede
mkdir -p /tmp/wd

# Fuzz the Unicorn proxy under Centipede 1000 times with parallelism of 30.
"${SILIFUZZ_BIN_DIR}/external/com_google_fuzztest/centipede/centipede" \
  --binary="${SILIFUZZ_BIN_DIR}/proxies/unicorn_x86_64" \
  --workdir=/tmp/wd \
  -j=30 --num_runs=1000
```

NOTE: Please refer to
[Centipede](https://github.com/google/fuzztest/blob/main/centipede/README.md#run-centipede-locally-)
documentation on how to efficiently run the fuzzing engine.

### Using pre-generated corpus

You can download Centipede corpus files that have been generated using the
instructions above
[here](https://storage.googleapis.com/silifuzz/corpus-unicorn-20221212.tar.bz2).
The data can be processed by `simple_fix_tool` or used to seed future fuzzing
runs.

## Tools

### silifuzz_platform_id

This helper tool is to check that the machine you're running on is supported.

```shell
$ ${SILIFUZZ_BIN_DIR}/tools/silifuzz_platform_id --short
```

```
intel-skylake
```

NOTE: SiliFuzz CPU detection logic does not account for certain desktop variants
of otherwise supported CPUs. The tool will report "Unsupported platform" in such
cases.

### fuzz_filter_tool

The
[fuzz_filter_tool](https://github.com/google/silifuzz/blob/main/tools/fuzz_filter_tool.cc)
converts raw instructions into Snap-compatible Snapshots. It returns 0 when the
conversion is possible and 1 otherwise. This interface is compatible with
Centipede
[input_filter](https://github.com/google/fuzztest/blob/main/centipede/environment.cc)

```
fuzz_filter_tool raw_input_sequence
```

The `raw_input_sequence` file contains raw instructions which will be converted
into the Snapshot format using
[InstructionsToSnapshot](https://github.com/google/silifuzz/blob/main/common/raw_insns_util.h)

Sample usage:

```shell
# INC EAX
echo -en '\xFF\xC0' > /tmp/inc_eax && ./tools/fuzz_filter_tool /tmp/inc_eax
echo $?
0
```

### snap_tool

`snap_tool` examines and manipulates binary Snapshot protos. It can optionally
load raw instructions and convert them to Snapshot.

```shell
echo -en '\xFF\xC0' > /tmp/inc_eax
./tools/snap_tool --raw print /tmp/inc_eax
```

```
Metadata:
  Id: inc_eax
  Architecture: x86_64 Linux
  Completeness: complete
Registers:
  gregs (non-0 only)
    rax = 0x20000000
    ....
```

### simple_fix_tool

The simple fix tool takes fuzzing results from Centipede, converts raw
instructions into a snapshots with no end states, adds end states to snapshots
and finally packages snapshots into a sharded relocatable snap corpus.

Currently this runs as a non-restartable process on a single host and everything
is put into memory so the size of corpus that can be handled is limited by
available memory of the host. Since end states are generated on the host, the
resulting corpus is single architecture.

### hashtest_generator

Experimental: hash tests are randomized structured tests that push entropy into
randomly generated instructions and capture the resulting outputs as efficiently
as possible. This approach is based on the observation that a non-trivial
percentage of defects can be detected by calling the right instruction with the
right input. Hash tests aggressively target this simple class of defect to
provide an experimental point of comparison for Silifuzz. Currently only x86_64
is supported.

If you want to generate, for example, 30k hash test snapshots containing
instructions supported by Skylake processors in the `/tmp/hashtest` directory,
you could run this command.

```shell
mkdir -p /tmp/hashtest && bazel run -c opt @silifuzz//fuzzer/hashtest:hashtest_generator -- --platform=intel-skylake -n 30000 --outdir /tmp/hashtest
```

## Frequently asked questions

The rest of the document is organized in a How-to manner with each question
describing a typical use case. The progression of the questions represents the
increasing complexity of the task one is trying to accomplish. Each step
typically requires either understanding or the artifacts (sometimes both)
obtained at the previous step.

NOTE: The document assumes an `x86_64` host/target CPU. The exact output may
vary depending on the CPU vendor/stepping/etc and the environment (e.g.
Docker/KVM).

WARNING: many of the instructions below execute **arbitrary** binary code with
the privileges of the running user. The tool does its best to sandbox the code
with seccomp(2). Use at your own risk.

### How to create a simple snapshot

```shell
# INC EAX
$ echo -en '\xFF\xC0' > /tmp/inc_eax
$ ./tools/snap_tool --raw  --out=/tmp/inc_eax.pb make /tmp/inc_eax
```

```shell
# CPUID
$ echo -en '\x0F\xA2' > /tmp/cpuid
$ ./tools/snap_tool --raw --out=/tmp/cpuid.pb make /tmp/cpuid
```

```
<error log omitted>
Could not load snapshot: INTERNAL: Tracing failed: Banned instruction: CPUID
```

NOTE: To avoid non-deterministic results, various parts of SiliFuzz exclude
certain classes of instructions, e.g. CPUID above.

### How to inspect a snapshot

```shell
$ ./tools/snap_tool print /tmp/inc_eax.pb
```

```
Metadata:
  Id: inc_eax
  Architecture: x86_64 Linux
  Completeness: complete
Registers:
  gregs (non-0 only):
    rax = 0x20000000
    rip = 0xeb85c12b000
    <omitted>
End states (1):
  Endpoint:
    Instruction address: 0xeb85c12b002
  Platforms:
    intel-skylake
  Registers (diff vs snapshot's initial values):
    gregs (modified only):
      rax = 0x20000001
      rip = 0xeb85c12b002
      <omitted>
```

Notice how the end state value of the `RAX` register is `0x20000001`
(`0x20000000+1` which is exactly what `INC EAX` does). Also notice that the
`RIP` value is the original `+2` which is the size of the `INC EAX` instruction.

### How to run a snapshot from a proto

```shell
$ ./tools/snap_tool play /tmp/inc_eax.pb
```

```
Snapshot played successfully.
```

### How to convert a single snapshot into a (relocatable) corpus

Note: You will need to specify a target platform in order to generate a corpus.
In this example, the resulting corpus targets the platform it was generated on.

```shell
$ cd "${SILIFUZZ_BIN_DIR}"
$ PLATFORM_ID=$(./tools/silifuzz_platform_id --short)

$ ./tools/snap_tool generate_corpus /tmp/inc_eax.pb \
--target_platform="${PLATFORM_ID}" > /tmp/inc_eax.corpus

# Will play the same "INC EAX" snapshot 1M times
$ ./runner/reading_runner_main_nolibc /tmp/inc_eax.corpus
```

You can inspect the process with gdb:

```shell
$ gdb ./runner/reading_runner_main_nolibc
```

```
(gdb) b RestoreUContextNoSyscalls
(gdb) run /tmp/inc_eax.corpus
Starting program: .../reading_runner_main_nolibc /tmp/inc_eax.corpus

Breakpoint 1, 0x0000456700010598 in RestoreUContextNoSyscalls ()
(gdb) x/i 0xeb85c12b000 # same as the rip value produced by snap_tool print above
   0xeb85c12b000:       inc    %eax
```

### How to create a corpus from an emulator

NOTE: This step relies on the "fuzzing Unicorn target" step described earlier.

Convert fuzzing result corpus.* into a 10-shard runnable corpus for the current
architecture.

```shell
cd "${SILIFUZZ_BIN_DIR}"

"${SILIFUZZ_BIN_DIR}/tools/simple_fix_tool_main" \
  --num_output_shards=10 \
  --output_path_prefix=/tmp/wd/runnable-corpus \
  /tmp/wd/corpus.*
```

The corpus shards will be at /tmp/wd/runnable-corpus.*

### How to inspect a corpus file

```shell
$ ./tools/snap_corpus_tool list_snaps /tmp/inc_eax.corpus
...
I0000 00:00:1661887744.019079 4074672 snap_corpus_tool.cc:155] inc_eax
```

NOTE: This is a very basic tool at the moment offering just a few commands.

### How to invoke the runner to scan a single core of a CPU

```shell
# Will play the same "INC EAX" snapshot on CPU#1 10k times.
$ ./runner/reading_runner_main_nolibc \
    --cpu=1 --num_iterations=10000 /tmp/inc_eax.corpus
```

### How to scan all cores of a CPU

The orchestrator will cycle through all the shards listed in the file passed in
`--shard_list_file` argument.

```shell
$ ls -1 /tmp/wd/runnable-corpus.* > /tmp/shard_list
# Will repeatedly run the corpus on all available CPU cores for 30s using
# /tmp/wd/runnable-corpus.* selected randomly.
$ ./orchestrator/silifuzz_orchestrator_main --duration=30s \
     --runner=./runner/reading_runner_main_nolibc \
     --shard_list_file=/tmp/shard_list
```

NOTE: The orchestrator can also load XZ-compressed corpus shards from files
ending with `.xz`
