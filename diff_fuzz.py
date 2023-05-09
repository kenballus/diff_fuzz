#############################################################################################
# diff_fuzz.py
# This is a wrapper around afl-showmap that does differential fuzzing a la
#   https://github.com/nezha-dt/nezha, but much slower.
# Fuzzing targets are configured in `config.py`.
#############################################################################################

import sys
import subprocess
import multiprocessing
import random
import functools
import itertools
import os
import re
from pathlib import PosixPath
from typing import List, Set, FrozenSet, Tuple, Callable

try:
    from tqdm import tqdm  # type: ignore
except ModuleNotFoundError:
    tqdm = lambda it, **kwargs: it  # type: ignore

import config

HAS_GRAMMAR: bool = False
try:
    from grammar import generate_random_matching_input, grammar_re, grammar_dict  # type: ignore

    print("Importing grammar from `grammar.py`.", file=sys.stderr)
    HAS_GRAMMAR = True
except ModuleNotFoundError:
    print("`grammar.py` not found; disabling grammar-based mutation.", file=sys.stderr)

try:
    from normalization import normalize  # type: ignore
except ModuleNotFoundError:
    print("`normalization.py` not found; disabling stdout normalizers.", file=sys.stderr)
    normalize = lambda x, _: x  # type: ignore

assert config.SEED_DIR.is_dir()
SEED_INPUTS: List[PosixPath] = list(
    map(lambda s: config.SEED_DIR.joinpath(PosixPath(s)), os.listdir(config.SEED_DIR))
)

assert all(map(lambda tc: tc.executable.exists(), config.TARGET_CONFIGS))

fingerprint_t = Tuple[FrozenSet[int], ...]


def grammar_mutate(m: re.Match, _: bytes) -> bytes:
    # This function takes _ so it can have the same
    # signature as the other mutators after currying with m,
    # even though _ is ignored.
    rule_name, orig_rule_match = random.choice(list(filter(lambda p: bool(p[1]), m.groupdict().items())))
    new_rule_match: str = generate_random_matching_input(grammar_dict[rule_name])

    # This has a chance of being wrong, but that's okay in my opinion
    slice_index: int = m.string.index(orig_rule_match)

    return bytes(
        m.string[:slice_index] + new_rule_match + m.string[slice_index + len(orig_rule_match) :],
        "UTF-8",
    )


def byte_change(b: bytes) -> bytes:
    index: int = random.randint(0, len(b) - 1)
    return b[:index] + bytes([random.randint(0, 255)]) + b[index + 1 :]


def byte_insert(b: bytes) -> bytes:
    index: int = random.randint(0, len(b))
    return b[:index] + bytes([random.randint(0, 255)]) + b[index:]


def byte_delete(b: bytes) -> bytes:
    index: int = random.randint(0, len(b) - 1)
    return b[:index] + b[index + 1 :]


def mutate_input(b: bytes) -> bytes:
    mutators: List[Callable[[bytes], bytes]] = [byte_insert]
    if len(b) > 0:
        mutators.append(byte_change)
    if len(b) > 1:
        mutators.append(byte_delete)
    if HAS_GRAMMAR:
        try:
            m: re.Match | None = re.match(grammar_re, str(b, "UTF-8"))
            if m is not None:
                mutators.append(functools.partial(grammar_mutate, m))
        except UnicodeDecodeError:
            pass

    return random.choice(mutators)(b)


def parse_tracer_output(tracer_output: bytes) -> FrozenSet[int]:
    result: Set[int] = set()
    for line in tracer_output.split(b"\n"):
        try:
            edge, _ = map(int, line.strip().split(b":"))
            result.add(edge)
        except ValueError:
            pass
    return frozenset(result)


def make_command_line(tc: config.TargetConfig) -> List[str]:
    command_line: List[str] = []
    if tc.needs_tracing:
        if tc.needs_python_afl:
            command_line.append("py-afl-showmap")
        else:
            command_line.append("afl-showmap")
            if tc.needs_qemu:  # Enable QEMU mode, if necessary
                command_line.append("-Q")
        command_line.append("-e")  # Only care about edge coverage; ignore hit counts
        command_line += ["-o", "/dev/stdout"]
        command_line += ["-t", str(config.TIMEOUT_TIME)]
        command_line.append("--")

    if tc.needs_python_afl:
        command_line.append("python3")
    command_line.append(str(tc.executable.resolve()))
    command_line += tc.cli_args

    return command_line


def minimize_differential(bug_inducing_input: bytes) -> bytes:
    _, orig_statuses, orig_stdouts = run_executables(bug_inducing_input, disable_tracing=True)

    orig_stdout_comparisons: Tuple[bool, ...] = (True,)
    if config.OUTPUT_DIFFERENTIALS_MATTER:
        orig_stdout_comparisons = tuple(
            itertools.starmap(bytes.__eq__, itertools.combinations(orig_stdouts, 2))
        )

    result: bytes = bug_inducing_input

    for deletion_length in config.DELETION_LENGTHS:
        i: int = len(result) - deletion_length
        while i > 0:
            reduced_form: bytes = result[:i] + result[i + deletion_length :]
            _, new_statuses, new_stdouts = run_executables(reduced_form)
            if (
                new_statuses == orig_statuses
                and (
                    tuple(itertools.starmap(bytes.__eq__, itertools.combinations(new_stdouts, 2)))
                    if config.OUTPUT_DIFFERENTIALS_MATTER
                    else (True,)
                )
                == orig_stdout_comparisons
            ):
                result = reduced_form
                i -= deletion_length
            else:
                i -= 1

    return result

@functools.lru_cache
def run_executables(
    current_input: bytes, disable_tracing: bool = False
) -> Tuple[fingerprint_t, Tuple[int, ...], Tuple[bytes, ...]]:
    traced_procs: List[subprocess.Popen | None] = []

    # We need these to extract exit statuses and stdouts
    untraced_procs: List[subprocess.Popen] = []

    for tc in config.TARGET_CONFIGS:
        command_line: List[str] = make_command_line(tc)
        if not disable_tracing and tc.needs_tracing:
            traced_proc: subprocess.Popen = subprocess.Popen(
                command_line,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=tc.env,
            )
            assert traced_proc.stdin is not None
            traced_proc.stdin.write(current_input)
            traced_proc.stdin.close()
            traced_procs.append(traced_proc)
        else:
            traced_procs.append(None)

        untraced_command_line: List[str] = (
            command_line[command_line.index("--") + 1 :] if tc.needs_tracing else command_line
        )
        untraced_proc: subprocess.Popen = subprocess.Popen(
            untraced_command_line,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE if config.OUTPUT_DIFFERENTIALS_MATTER else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=tc.env,
        )
        assert untraced_proc.stdin is not None
        untraced_proc.stdin.write(current_input)
        untraced_proc.stdin.close()
        untraced_procs.append(untraced_proc)

    # Wait for the processes to exit
    for proc in itertools.chain(traced_procs, untraced_procs):
        if proc is not None:
            proc.wait()

    # Extract their stdouts
    stdouts: List[bytes] = []
    for proc, tc in zip(untraced_procs, config.TARGET_CONFIGS):
        stdout_bytes: bytes = proc.stdout.read() if proc.stdout is not None else b""
        stdout_bytes = normalize(stdout_bytes, tc.encoding)
        stdouts.append(stdout_bytes)

    # Extract their traces
    traces: List[FrozenSet[int]] = []
    for tc, proc in zip(config.TARGET_CONFIGS, traced_procs):
        traces.append(
            parse_tracer_output(proc.stdout.read() if proc is not None and proc.stdout is not None else b"")
        )

    fingerprint: fingerprint_t = tuple(traces)

    statuses: Tuple[int, ...] = (
        tuple(proc.returncode for proc in untraced_procs)
        if config.EXIT_STATUSES_MATTER
        else tuple(int(proc.returncode != 0) for proc in untraced_procs)
    )
    return fingerprint, statuses, tuple(stdouts)


def main() -> None:
    if len(sys.argv) > 2:
        print(f"Usage: python3 {sys.argv[0]}", file=sys.stderr)
        sys.exit(1)

    input_queue: List[bytes] = []
    for seed_input in SEED_INPUTS:
        with open(seed_input, "rb") as f:
            input_queue.append(f.read())

    # One input `I` produces one trace per program being fuzzed.
    # Convert each trace to a (frozen)set of edges by deduplication.
    # Pack those sets together in a tuple (and maybe hash it).
    # This is a fingerprint of the programs' execution on the input `I`.
    # Keep these fingerprints in a set.
    # An input is worth mutation if its fingerprint is new.
    fingerprints: Set[fingerprint_t] = set()
    minimized_fingerprints: Set[fingerprint_t] = set()

    generation: int = 0
    differentials: List[bytes] = []

    while len(input_queue) != 0:  # While there are still inputs to check,
        print(f"Starting generation {generation}.", file=sys.stderr)
        with multiprocessing.Pool(processes=os.cpu_count()) as pool:
            # run the programs on the things in the input queue.
            fingerprint_and_statuses_and_stdouts = tqdm(
                pool.imap(run_executables, input_queue),
                desc="Running targets",
                total=len(input_queue),
            )

            mutation_candidates: List[bytes] = []

            for current_input, (fingerprint, statuses, stdouts) in zip(
                input_queue, fingerprint_and_statuses_and_stdouts
            ):
                # If we found something new, mutate it and add its children to the input queue
                # If we get one program to fail while another succeeds, then we're doing good.
                if fingerprint not in fingerprints:
                    fingerprints.add(fingerprint)
                    status_set: Set[int] = set(statuses)
                    if (len(status_set) != 1) or (status_set == {0} and len(set(stdouts)) != 1):
                        minimized_input: bytes = minimize_differential(current_input)
                        minimized_fingerprint, _, _ = run_executables(minimized_input)
                        if minimized_fingerprint not in minimized_fingerprints:
                            differentials.append(minimized_input)
                            minimized_fingerprints.add(minimized_fingerprint)
                    else:
                        mutation_candidates.append(current_input)

        input_queue.clear()
        while len(mutation_candidates) != 0 and len(input_queue) < config.ROUGH_DESIRED_QUEUE_LEN:
            input_queue += list(map(mutate_input, mutation_candidates))

        print(
            f"End of generation {generation}.\n"
            + f"Differentials:\t\t{len(differentials)}\n"
            + f"Mutation candidates:\t{len(mutation_candidates)}",
            file=sys.stderr,
        )
        generation += 1

    if len(differentials) != 0:
        print("Differentials:", file=sys.stderr)
        print("\n".join(repr(b) for b in differentials))
    else:
        print("No differentials found! Try increasing config.ROUGH_DESIRED_QUEUE_LEN.", file=sys.stderr)


if __name__ == "__main__":
    main()
