// Copyright 2022 The SiliFuzz Authors.
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

        .text
        .p2align 2
        .globl  RestoreUContextView
        .type   RestoreUContextView, @function
RestoreUContextView:
#include "restore_ucontext_body.inc"
        .size   RestoreUContextView, .-RestoreUContextView
        .section        .note.GNU-stack,"",@progbits
