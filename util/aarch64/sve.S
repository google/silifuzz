// Copyright 2024 The SiliFuzz Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Utility functions for handling Z, P, and FFR registers used by SVE
// instructions.

        .text

        // Enable assembling of SVE instructions.
        .arch_extension sve

// Loads z0-z31 from address in x0.
        .p2align 4
        .globl  LoadZRegisters
        .type   LoadZRegisters, @function
LoadZRegisters:
        ldr     z0,  [x0, #0,  mul vl]
        ldr     z1,  [x0, #1,  mul vl]
        ldr     z2,  [x0, #2,  mul vl]
        ldr     z3,  [x0, #3,  mul vl]
        ldr     z4,  [x0, #4,  mul vl]
        ldr     z5,  [x0, #5,  mul vl]
        ldr     z6,  [x0, #6,  mul vl]
        ldr     z7,  [x0, #7,  mul vl]
        ldr     z8,  [x0, #8,  mul vl]
        ldr     z9,  [x0, #9,  mul vl]
        ldr     z10, [x0, #10, mul vl]
        ldr     z11, [x0, #11, mul vl]
        ldr     z12, [x0, #12, mul vl]
        ldr     z13, [x0, #13, mul vl]
        ldr     z14, [x0, #14, mul vl]
        ldr     z15, [x0, #15, mul vl]
        ldr     z16, [x0, #16, mul vl]
        ldr     z17, [x0, #17, mul vl]
        ldr     z18, [x0, #18, mul vl]
        ldr     z19, [x0, #19, mul vl]
        ldr     z20, [x0, #20, mul vl]
        ldr     z21, [x0, #21, mul vl]
        ldr     z22, [x0, #22, mul vl]
        ldr     z23, [x0, #23, mul vl]
        ldr     z24, [x0, #24, mul vl]
        ldr     z25, [x0, #25, mul vl]
        ldr     z26, [x0, #26, mul vl]
        ldr     z27, [x0, #27, mul vl]
        ldr     z28, [x0, #28, mul vl]
        ldr     z29, [x0, #29, mul vl]
        ldr     z30, [x0, #30, mul vl]
        ldr     z31, [x0, #31, mul vl]

        ret
        .size   LoadZRegisters, .-LoadZRegisters

// Saves z0-z31 to address in x0.
        .p2align 4
        .globl  StoreZRegisters
        .type   StoreZRegisters, @function
StoreZRegisters:
        str     z0,  [x0, #0,  mul vl]
        str     z1,  [x0, #1,  mul vl]
        str     z2,  [x0, #2,  mul vl]
        str     z3,  [x0, #3,  mul vl]
        str     z4,  [x0, #4,  mul vl]
        str     z5,  [x0, #5,  mul vl]
        str     z6,  [x0, #6,  mul vl]
        str     z7,  [x0, #7,  mul vl]
        str     z8,  [x0, #8,  mul vl]
        str     z9,  [x0, #9,  mul vl]
        str     z10, [x0, #10, mul vl]
        str     z11, [x0, #11, mul vl]
        str     z12, [x0, #12, mul vl]
        str     z13, [x0, #13, mul vl]
        str     z14, [x0, #14, mul vl]
        str     z15, [x0, #15, mul vl]
        str     z16, [x0, #16, mul vl]
        str     z17, [x0, #17, mul vl]
        str     z18, [x0, #18, mul vl]
        str     z19, [x0, #19, mul vl]
        str     z20, [x0, #20, mul vl]
        str     z21, [x0, #21, mul vl]
        str     z22, [x0, #22, mul vl]
        str     z23, [x0, #23, mul vl]
        str     z24, [x0, #24, mul vl]
        str     z25, [x0, #25, mul vl]
        str     z26, [x0, #26, mul vl]
        str     z27, [x0, #27, mul vl]
        str     z28, [x0, #28, mul vl]
        str     z29, [x0, #29, mul vl]
        str     z30, [x0, #30, mul vl]
        str     z31, [x0, #31, mul vl]

        ret
        .size   StoreZRegisters, .-StoreZRegisters

// Clears z0-z31 to zero.
        .p2align 4
        .globl  ClearZRegisters
        .type   ClearZRegisters, @function
ClearZRegisters:
        eor     z0.d,  z0.d,  z0.d
        eor     z1.d,  z1.d,  z1.d
        eor     z2.d,  z2.d,  z2.d
        eor     z3.d,  z3.d,  z3.d
        eor     z4.d,  z4.d,  z4.d
        eor     z5.d,  z5.d,  z5.d
        eor     z6.d,  z6.d,  z6.d
        eor     z7.d,  z7.d,  z7.d
        eor     z8.d,  z8.d,  z8.d
        eor     z9.d,  z9.d,  z9.d
        eor     z10.d, z10.d, z10.d
        eor     z11.d, z11.d, z11.d
        eor     z12.d, z12.d, z12.d
        eor     z13.d, z13.d, z13.d
        eor     z14.d, z14.d, z14.d
        eor     z15.d, z15.d, z15.d
        eor     z16.d, z16.d, z16.d
        eor     z17.d, z17.d, z17.d
        eor     z18.d, z18.d, z18.d
        eor     z19.d, z19.d, z19.d
        eor     z20.d, z20.d, z20.d
        eor     z21.d, z21.d, z21.d
        eor     z22.d, z22.d, z22.d
        eor     z23.d, z23.d, z23.d
        eor     z24.d, z24.d, z24.d
        eor     z25.d, z25.d, z25.d
        eor     z26.d, z26.d, z26.d
        eor     z27.d, z27.d, z27.d
        eor     z28.d, z28.d, z28.d
        eor     z29.d, z29.d, z29.d
        eor     z30.d, z30.d, z30.d
        eor     z31.d, z31.d, z31.d

        ret
        .size   ClearZRegisters, .-ClearZRegisters

// Loads p0-p15 from address in x0.
        .p2align 4
        .globl  LoadPRegisters
        .type   LoadPRegisters, @function
LoadPRegisters:
        ldr     p0,  [x0, #0,  mul vl]
        ldr     p1,  [x0, #1,  mul vl]
        ldr     p2,  [x0, #2,  mul vl]
        ldr     p3,  [x0, #3,  mul vl]
        ldr     p4,  [x0, #4,  mul vl]
        ldr     p5,  [x0, #5,  mul vl]
        ldr     p6,  [x0, #6,  mul vl]
        ldr     p7,  [x0, #7,  mul vl]
        ldr     p8,  [x0, #8,  mul vl]
        ldr     p9,  [x0, #9,  mul vl]
        ldr     p10, [x0, #10, mul vl]
        ldr     p11, [x0, #11, mul vl]
        ldr     p12, [x0, #12, mul vl]
        ldr     p13, [x0, #13, mul vl]
        ldr     p14, [x0, #14, mul vl]
        ldr     p15, [x0, #15, mul vl]

        ret
        .size   LoadPRegisters, .-LoadPRegisters

// Saves p0-p15 to address in x0.
        .p2align 4
        .globl  StorePRegisters
        .type   StorePRegisters, @function
StorePRegisters:
        str     p0,  [x0, #0,  mul vl]
        str     p1,  [x0, #1,  mul vl]
        str     p2,  [x0, #2,  mul vl]
        str     p3,  [x0, #3,  mul vl]
        str     p4,  [x0, #4,  mul vl]
        str     p5,  [x0, #5,  mul vl]
        str     p6,  [x0, #6,  mul vl]
        str     p7,  [x0, #7,  mul vl]
        str     p8,  [x0, #8,  mul vl]
        str     p9,  [x0, #9,  mul vl]
        str     p10, [x0, #10, mul vl]
        str     p11, [x0, #11, mul vl]
        str     p12, [x0, #12, mul vl]
        str     p13, [x0, #13, mul vl]
        str     p14, [x0, #14, mul vl]
        str     p15, [x0, #15, mul vl]

        ret
        .size   StorePRegisters, .-StorePRegisters

// Clears p0-p15 to zero.
        .p2align 4
        .globl  ClearPRegisters
        .type   ClearPRegisters, @function
ClearPRegisters:
        eor     p0.b,  p0/z,  p0.b,  p0.b
        eor     p1.b,  p1/z,  p1.b,  p1.b
        eor     p2.b,  p2/z,  p2.b,  p2.b
        eor     p3.b,  p3/z,  p3.b,  p3.b
        eor     p4.b,  p4/z,  p4.b,  p4.b
        eor     p5.b,  p5/z,  p5.b,  p5.b
        eor     p6.b,  p6/z,  p6.b,  p6.b
        eor     p7.b,  p7/z,  p7.b,  p7.b
        eor     p8.b,  p8/z,  p8.b,  p8.b
        eor     p9.b,  p9/z,  p9.b,  p9.b
        eor     p10.b, p10/z, p10.b, p10.b
        eor     p11.b, p11/z, p11.b, p11.b
        eor     p12.b, p12/z, p12.b, p12.b
        eor     p13.b, p13/z, p13.b, p13.b
        eor     p14.b, p14/z, p14.b, p14.b
        eor     p15.b, p15/z, p15.b, p15.b

        ret
        .size   ClearPRegisters, .-ClearPRegisters

// Loads ffr from address in x0.
// Warning: This clobbers the p0 register.
        .p2align 4
        .globl  LoadFfrRegister
        .type   LoadFfrRegister, @function
LoadFfrRegister:
        ldr     p0,  [x0]
        wrffr   p0.b

        ret
        .size   LoadFfrRegister, .-LoadFfrRegister

// Saves ffr to address in x0.
// Warning: This clobbers the p0 register.
        .p2align 4
        .globl  StoreFfrRegister
        .type   StoreFfrRegister, @function
StoreFfrRegister:
        rdffr   p0.b
        str     p0,  [x0]

        ret
        .size   StoreFfrRegister, .-StoreFfrRegister

// Clears ffr to zero.
// Warning: This clobbers the p0 register.
        .p2align 4
        .globl  ClearFfrRegister
        .type   ClearFfrRegister, @function
ClearFfrRegister:
        pfalse  p0.b
        wrffr   p0.b

        ret
        .size   ClearFfrRegister, .-ClearFfrRegister
