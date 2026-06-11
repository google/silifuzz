# Copyright 2026 The SiliFuzz Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Minimization schedule passes (The Policy).

Defines minimization algorithms and mutation schedules. Accepts a
DifferentialEngine instance via dependency injection to execute candidate
mutations.
"""

from collections.abc import Callable, Mapping, Sequence
import enum
import random
import types
from typing import TypeVar

from absl import logging

from proto import snapshot_pb2
from tools.minimizer import engine
from tools.minimizer import insn
from tools.minimizer import schedule_pb2


class PassKind(enum.StrEnum):
  """A minimization pass kind."""

  NOP = "NOP"  # Replace instructions with NOP(s).
  FUSE = "FUSE"  # Fuse adjacent canonical NOPs.
  SWAP = "SWAP"  # Swap NOP with adjacent instruction.
  ELIDE = "ELIDE"  # Skip NOP(s).
  OMIT = "OMIT"  # Remove NOP(s).


PassFunction = Callable[
    [engine.DifferentialEngine, schedule_pb2.PassConfig], bool
]

_CandidateT = TypeVar("_CandidateT")

MAX_BUDGET = 2_147_483_647
DEFAULT_MAX_CONSECUTIVE_FAILURES = 10  # Following original THRESHOLD cutoff.


def default_pass_config() -> schedule_pb2.PassConfig:
  """Creates a fresh PassConfig protobuf instance populated with default baseline budgets.

  Returns:
    A PassConfig protobuf instance with default budgets.
  """
  return schedule_pb2.PassConfig(
      max_successes=MAX_BUDGET,
      max_consecutive_failures=DEFAULT_MAX_CONSECUTIVE_FAILURES,
      max_iterations=MAX_BUDGET,
  )


def run_iterative_pass(
    pass_name: str,
    diff_engine: engine.DifferentialEngine,
    config: schedule_pb2.PassConfig,
    find_candidates_fn: Callable[[Sequence[insn.Insn]], Sequence[_CandidateT]],
    mutate_candidate_fn: Callable[[_CandidateT], bool],
    *,
    pass_default_order: schedule_pb2.PassConfig.CandidateOrder = (
        schedule_pb2.PassConfig.RANDOM_ORDER
    ),
    mutation_invalidates_candidates: bool = False,
) -> bool:
  """Executes a generic iterative minimization pass across convergence rounds.

  Args:
    pass_name: Name of the pass for logging (e.g., "nop_pass").
    diff_engine: The DifferentialEngine instance managing the active snapshot.
    config: Configuration defining budget limits.
    find_candidates_fn: A callable accepting parsed trace instructions and
      returning a list of candidate items.
    mutate_candidate_fn: A callable accepting a single candidate item and
      returning True if the mutation succeeded, False otherwise.
    pass_default_order: Default candidate execution order for the pass.
    mutation_invalidates_candidates: Whether a successful mutation by
      mutate_candidate_fn alters the snapshot structure (e.g., shifting memory
      offsets during byte deletion in omit_pass) such that remaining candidates
      in the current round become invalid. If True, the inner candidate loop
      aborts immediately upon success to re-trace fresh instruction addresses in
      the next outer convergence round.

  Returns:
    True if any mutation succeeded, False otherwise.
  """
  logging.info("%s: running on snapshot %s", pass_name, diff_engine.snapshot_id)

  success_count = 0
  consecutive_failures = 0

  for outer_iter in range(config.max_iterations):
    try:
      insns = diff_engine.trace_insns()
    except RuntimeError:
      logging.warning(
          "%s: failed to trace instructions for snapshot %s",
          pass_name,
          diff_engine.snapshot_id,
          exc_info=True,
      )
      break

    candidates = list(find_candidates_fn(insns))
    logging.info(
        "%s: candidates: %d (round %d)",
        pass_name,
        len(candidates),
        outer_iter,
    )
    if not candidates:
      break

    order = (
        config.candidate_order
        if config.candidate_order != schedule_pb2.PassConfig.DEFAULT_ORDER
        else pass_default_order
    )

    if order == schedule_pb2.PassConfig.FORWARD_ORDER:
      pass
    elif order == schedule_pb2.PassConfig.REVERSE_ORDER:
      candidates.reverse()
    elif order == schedule_pb2.PassConfig.RANDOM_ORDER:
      seed = config.seed if config.HasField("seed") else diff_engine.snapshot_id
      rng = random.Random(seed)
      rng.shuffle(candidates)

    modified_in_round = False
    for victim in candidates:
      if success_count >= config.max_successes:
        break
      if consecutive_failures >= config.max_consecutive_failures:
        break

      if not mutate_candidate_fn(victim):
        consecutive_failures += 1
        continue

      modified_in_round = True
      success_count += 1
      consecutive_failures = 0
      if mutation_invalidates_candidates:
        break

    if success_count >= config.max_successes:
      logging.info(
          "%s: reached max_successes (%d) in round %d",
          pass_name,
          config.max_successes,
          outer_iter,
      )
      break
    if consecutive_failures >= config.max_consecutive_failures:
      logging.info(
          "%s: reached max_consecutive_failures (%d) in round %d",
          pass_name,
          config.max_consecutive_failures,
          outer_iter,
      )
      break
    if not modified_in_round:
      logging.info(
          "%s: no modifications in round %d",
          pass_name,
          outer_iter,
      )
      break

  return success_count > 0


def nop_pass(
    diff_engine: engine.DifferentialEngine,
    config: schedule_pb2.PassConfig | None = None,
) -> bool:
  """Attempts NOP-ing out active instructions in the snapshot.

  Iterates through active (non-NOP) candidates in a randomized order, attempting
  to replace each with architecture-specific NOP bytes. The pass repeats across
  outer convergence rounds until the configured budget bounds (max_successes,
  max_consecutive_failures, max_iterations) or candidate pools are exhausted.

  Args:
    diff_engine: The DifferentialEngine instance managing the active snapshot.
    config: Configuration defining budget limits (max_successes,
      max_consecutive_failures, max_iterations).

  Returns:
    True if any instruction was successfully NOP-ed, False otherwise.
  """
  config = config if config is not None else default_pass_config()
  arch = diff_engine.architecture

  def _mutate(victim: insn.Insn) -> bool:
    logging.info("nop_pass: attempting NOP replacement for victim: %r", victim)
    try:
      filler = insn.nop_sequence_bytes(arch, victim.len)
    except ValueError:
      logging.warning(
          "nop_pass: failed to generate NOP bytes for victim: %r",
          victim,
          exc_info=True,
      )
      return False

    if diff_engine.try_modify(
        lambda out, v_addr=victim.addr, f_data=filler: diff_engine.set_bytes(
            out, v_addr, f_data
        )
    ):
      logging.info(
          "nop_pass: successfully NOP-ed instruction at %#x", victim.addr
      )
      return True
    return False

  return run_iterative_pass(
      pass_name="nop_pass",
      diff_engine=diff_engine,
      config=config,
      find_candidates_fn=lambda insns: [x for x in insns if not x.is_nop()],
      mutate_candidate_fn=_mutate,
      pass_default_order=schedule_pb2.PassConfig.RANDOM_ORDER,
      mutation_invalidates_candidates=False,
  )


def fuse_pass(
    diff_engine: engine.DifferentialEngine,
    config: schedule_pb2.PassConfig | None = None,
) -> bool:
  """Attempts fusing adjacent NOP sequences into multi-byte single NOPs.

  Iterates through contiguous NOP sequences in a randomized order, attempting
  to replace each sequence with a single multi-byte NOP opcode. The pass repeats
  across outer convergence rounds until the configured budget bounds
  (max_successes, max_consecutive_failures, max_iterations) or candidate pools
  are exhausted.

  Args:
    diff_engine: The DifferentialEngine instance managing the active snapshot.
    config: Configuration defining budget limits (max_successes,
      max_consecutive_failures, max_iterations).

  Returns:
    True if any NOP sequence was successfully fused, False otherwise.
  """
  config = config if config is not None else default_pass_config()
  arch = diff_engine.architecture
  min_nop_len = insn.MIN_NOP_LEN_BY_ARCH[arch]
  max_nop_len = insn.MAX_NOP_LEN_BY_ARCH[arch]

  def _find_candidates(insns: Sequence[insn.Insn]) -> list[insn.NopSequence]:
    nop_sequences: list[insn.NopSequence] = []
    for x in insns:
      if not x.is_simple_nop(arch):
        continue
      if not nop_sequences:
        nop_sequences.append(insn.NopSequence(x.addr, x.len))
        continue
      last_sequence = nop_sequences[-1]
      if last_sequence.addr + last_sequence.len != x.addr:
        nop_sequences.append(insn.NopSequence(x.addr, x.len))
        continue
      last_sequence.len += x.len
    return [x for x in nop_sequences if x.len > min_nop_len]

  def _mutate(victim: insn.NopSequence) -> bool:
    logging.info(
        "fuse_pass: Attempting NOP fusion for victim sequence: %r", victim
    )
    max_filler_len = min(max_nop_len, victim.len)
    # The smallest NOP is not a filler candidate as it fuses nothing.
    for filler_len in range(max_filler_len, min_nop_len, -1):
      try:
        filler = insn.single_nop_bytes(arch, filler_len)
      except ValueError:
        logging.warning(
            "fuse_pass: Failed to generate single NOP of len %d",
            filler_len,
            exc_info=True,
        )
        continue

      if diff_engine.try_modify(
          lambda out, v_addr=victim.addr, f_data=filler: diff_engine.set_bytes(
              out, v_addr, f_data
          )
      ):
        logging.info(
            "fuse_pass: Successfully fused NOPs at %#x with size %d",
            victim.addr,
            filler_len,
        )
        return True
    return False

  return run_iterative_pass(
      pass_name="fuse_pass",
      diff_engine=diff_engine,
      config=config,
      find_candidates_fn=_find_candidates,
      mutate_candidate_fn=_mutate,
      pass_default_order=schedule_pb2.PassConfig.RANDOM_ORDER,
      mutation_invalidates_candidates=False,
  )


def swap_pass(
    diff_engine: engine.DifferentialEngine,
    config: schedule_pb2.PassConfig | None = None,
) -> bool:
  """Attempts swapping active instructions with succeeding NOP instructions.

  Iterates through adjacent instruction pairs in a randomized order, identifying
  candidate pairs where an active instruction is immediately followed by a NOP.
  The active instruction is swapped with the succeeding NOP to bubble active
  instructions toward the basic block exit. The pass repeats across outer
  convergence rounds until the configured budget bounds (max_successes,
  max_consecutive_failures, max_iterations) or candidate pools are exhausted.

  Args:
    diff_engine: The DifferentialEngine instance managing the active snapshot.
    config: Configuration defining budget limits (max_successes,
      max_consecutive_failures, max_iterations).

  Returns:
    True if any swap succeeded, False otherwise.
  """
  config = config if config is not None else default_pass_config()

  def _find_candidates(
      insns: Sequence[insn.Insn],
  ) -> list[tuple[insn.Insn, insn.Insn]]:
    candidates = []
    for l_insn, r_insn in zip(insns, insns[1:]):
      if l_insn.is_nop():
        continue
      if not r_insn.is_nop():
        continue
      if l_insn.addr + l_insn.len != r_insn.addr:
        continue
      candidates.append((l_insn, r_insn))
    return candidates

  def _mutate(victim: tuple[insn.Insn, insn.Insn]) -> bool:
    l_insn, r_insn = victim
    logging.info("swap_pass: swapping insn %r and insn %r", l_insn, r_insn)
    try:
      raw_data = diff_engine.get_bytes(l_insn.addr, l_insn.len + r_insn.len)
    except ValueError:
      logging.warning(
          "swap_pass: failed to get bytes for insns %r, %r",
          l_insn,
          r_insn,
          exc_info=True,
      )
      return False

    swapped_data = raw_data[l_insn.len :] + raw_data[: l_insn.len]

    if diff_engine.try_modify(
        lambda out, v_addr=l_insn.addr, s_data=swapped_data: diff_engine.set_bytes(
            out, v_addr, s_data
        )
    ):
      logging.info(
          "swap_pass: successfully swapped instruction at %#x", l_insn.addr
      )
      return True
    return False

  return run_iterative_pass(
      pass_name="swap_pass",
      diff_engine=diff_engine,
      config=config,
      find_candidates_fn=_find_candidates,
      mutate_candidate_fn=_mutate,
      pass_default_order=schedule_pb2.PassConfig.RANDOM_ORDER,
      mutation_invalidates_candidates=False,
  )


def elide_pass(
    diff_engine: engine.DifferentialEngine,
    config: schedule_pb2.PassConfig | None = None,
) -> bool:
  """Attempts eliding leading NOPs by advancing the initial instruction pointer (PC/RIP).

  Traces the snapshot to find the first active (non-NOP) instruction and
  advances the initial instruction pointer to skip all leading NOPs. As this
  operation eliminates all leading NOPs in a single step, it executes exactly
  once without outer convergence loops.

  Args:
    diff_engine: The DifferentialEngine instance managing the active snapshot.
    config: Configuration defining budget limits (max_successes,
      max_consecutive_failures, max_iterations).

  Returns:
    True if initial PC advancement succeeded, False otherwise.
  """
  del config
  logging.info("elide_pass: running on snapshot %s", diff_engine.snapshot_id)

  try:
    insns = diff_engine.trace_insns()
  except RuntimeError:
    logging.warning(
        "elide_pass: failed to trace instructions for snapshot %s",
        diff_engine.snapshot_id,
        exc_info=True,
    )
    return False

  next_effective_insn = next((x for x in insns if not x.is_nop()), None)
  if next_effective_insn is None:
    logging.warning("elide_pass: no effective instruction found")
    return False

  orig_pc = insns[0].addr
  target_pc = next_effective_insn.addr

  logging.info("elide_pass: attempting PC elision to target: %#x", target_pc)
  if orig_pc == target_pc:
    logging.info(
        "elide_pass: PC is already at active instruction %#x", target_pc
    )
    return False

  if diff_engine.try_modify(
      lambda out, target_pc=target_pc: diff_engine.set_pc(out, target_pc)
  ):
    logging.info(
        "elide_pass: successfully elided top NOPs, advancing PC to %#x",
        target_pc,
    )
    return True
  return False


def omit_pass(
    diff_engine: engine.DifferentialEngine,
    config: schedule_pb2.PassConfig | None = None,
) -> bool:
  """Attempts omitting NOP instructions from the snapshot in place.

  Iterates through candidate NOP instructions in forward execution order,
  attempting to delete each NOP from the memory block. Because deleting bytes
  shifts the memory offsets of all subsequent instructions, a successful
  omission invalidates remaining candidates in the current round. The pass
  immediately breaks to re-trace fresh instruction addresses in the next outer
  convergence round, repeating until budget bounds (max_successes,
  max_consecutive_failures, max_iterations) or candidate pools are exhausted.

  Args:
    diff_engine: The DifferentialEngine instance managing the active snapshot.
    config: Configuration defining budget limits (max_successes,
      max_consecutive_failures, max_iterations).

  Returns:
    True if any NOP was successfully omitted, False otherwise.
  """
  config = config if config is not None else default_pass_config()

  def _mutate(victim: insn.Insn) -> bool:
    logging.info("omit_pass: attempting omission of victim: %r", victim)
    if diff_engine.try_modify(
        lambda out, v_addr=victim.addr, v_len=victim.len: diff_engine.delete_bytes(
            out, v_addr, v_len
        )
    ):
      logging.info("omit_pass: successfully omitted NOP at %#x", victim.addr)
      return True
    return False

  return run_iterative_pass(
      pass_name="omit_pass",
      diff_engine=diff_engine,
      config=config,
      find_candidates_fn=lambda insns: [x for x in insns if x.is_nop()],
      mutate_candidate_fn=_mutate,
      pass_default_order=schedule_pb2.PassConfig.FORWARD_ORDER,
      mutation_invalidates_candidates=True,
  )


# Mapping of PassKind to minimization passes.
PASS_FN_BY_KIND: Mapping[PassKind, PassFunction] = types.MappingProxyType({
    PassKind.NOP: nop_pass,
    PassKind.FUSE: fuse_pass,
    PassKind.SWAP: swap_pass,
    PassKind.ELIDE: elide_pass,
    PassKind.OMIT: omit_pass,
})

# Default minimization schedules by architecture.
DEFAULT_PASSES_BY_ARCH: Mapping[
    snapshot_pb2.Snapshot.Architecture, Sequence[PassKind]
] = types.MappingProxyType({
    snapshot_pb2.Snapshot.X86_64: (
        PassKind.NOP,
        PassKind.FUSE,
        PassKind.SWAP,
        PassKind.ELIDE,
    ),
    snapshot_pb2.Snapshot.AARCH64: (
        PassKind.NOP,
        PassKind.SWAP,
        PassKind.OMIT,
        PassKind.ELIDE,
    ),
})
