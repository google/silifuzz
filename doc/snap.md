# Silifuzz Snap Data Structure

## Overview

This document describes the Snap structure used in SiliFuzz. The Snap data
structure consists of a top-level Snap type and several component types. At the
highest level, it describes a fragment of computation, also known as a
[Snapshot](https://github.com/google/fuzzing/blob/master/docs/silifuzz.pdf)(#2.2).
A Snap consists of an initial state, some memory pages containing machines
instructions and data, and an expected end state. A Snap runner replays the
encoded computation by executing instructions using the initial states and
verifies that the actual end state matches the expected end state after
instructions are executed. The Snap data structure is heavily influenced by the
[silifuzz::Snapshot](https://github.com/google/silifuzz/blob/main/common/snapshot.h)
class used.

## Properties of Snap

*   Simplicity. Snap is designed to be as simple as possible to minimize the
    code size of a Snap runner that executes Snaps.
*   Execution efficiency. Snap is designed to support fast execution. It
    contains only information necessary for Snap execution.

## Snap

Snap is the high-level struct for representing snapshots in V2. It consists of
the following:

*   snapshot ID
*   memory mappings
*   initial memory bytes
*   initial register state
*   expected end state instruction address
*   expected end state register state
*   expected end state memory bytes

Snap evolved from Snapshot class though some simplifications have been made.
Snap only supports a single end state at a non exception throwing instruction.
As such, information formerly in
[Snapshot::EndState](https://github.com/google/silifuzz/blob/main/common/snapshot.h)
is now inlined into Snap.

## Array

Snap::Array is a template type used by Snap and other related types. It contains
the following information:

*   number of elements in array
*   a const pointer to the elements.

Snap::Array can only be used to contain const elements. Element storage is
allocated elsewhere to keep Snap::Array itself a fixed-sized struct. The
elements may have type-specific alignment and size requirements.

## MemoryMapping

MemoryMapping is a struct describing a mapped memory region, which consists of
one or more consecutive memory pages of the same set of memory permissions. It
contains the following information

*   start_address
*   limit_address
*   memory permissions

Both the start and limit addresses must fall on page boundaries. The limit
address is the address after the last byte covered by the mapping. The
permissions are encoded using same representation used by mmap() and mmprotect()
syscalls.

## MemoryBytes

Snap::MemoryBytes describes a block of contiguous byte data used by a snapshot.
It consists of the following:

*   start_address
*   memory permissions
*   byte data in an Array of uint8_t

To improve runtime efficiency, some constraints are imposed on
Snap::MemoryBytes. First, byte data are handled in 64-bit chunks. Therefore the
start address, the byte data size and the address of uint8_t Array elements must
be 64-bit aligned. Snap::MemoryBytes duplicates permissions information in
Snap::MemoryMapping for quick lookup. This requires all bytes in the MemoryBytes
to have the same memory permissions. If a block of bytes have different memory
permissions, the block must be broken up at permissions boundaries in order to
be representable by multiple consecutive Snap::MemoryBytes.

## RegisterState

Snap::RegisterState is an alias of
[silifuzz::UContext](https://github.com/google/silifuzz/blob/main/util/ucontext/ucontext.h)
type. It contains both GPR and FPR states. It is the same format used by
UContext saving and restoring functions so that a Snap runner can use the data
directly without any conversion. The types are also aligned especially for CPU
instructions handling register state. Unlike other Snap types, RegisterState is
not a POD type and a special constexpr constructor is used to make Snap
linker-initializable.

## Corpus

There is no special type defined for a Snap corpus. Instead, a Snap::Array of
const Snap pointers type is used. Since Snap lacks architectural information,
all Snaps in a corpus must be runnable on the same group of architectures.
