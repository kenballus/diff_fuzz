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
import io
import os
import re
from pathlib import PosixPath
from enum import Enum
from typing import List, Dict, Set, FrozenSet, Tuple, Callable, Optional

try:
    from tqdm import tqdm  # type: ignore
except ModuleNotFoundError:
    tqdm = lambda it, **kwargs: it  # type: ignore

from config import *

HAS_GRAMMAR: bool = False
try:
    from grammar import generate_random_matching_input, grammar_re, grammar_dict  # type: ignore

    print("Importing grammar from `grammar.py`.", file=sys.stderr)
    HAS_GRAMMAR = True
except:
    print("`grammar.py` not found; disabling grammar-based mutation.", file=sys.stderr)

HAS_NORMALIZATION: bool = False
try:
    from normalization import normalize # type: ignore
    HAS_NORMALIZATION = True
except:
    print("`normalization.py not found; disabling stdout normalizers.`", file=sys.stderr)

SEED_INPUTS: List[PosixPath] = list(map(SEED_DIR.joinpath, map(PosixPath, os.listdir(SEED_DIR))))

for tc in TARGET_CONFIGS:
    assert tc.executable.is_file()
assert TRACE_DIR.is_dir()
assert SEED_DIR.is_dir()
for seed in SEED_INPUTS:
    assert seed.is_file()

fingerprint_t = int


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


def mutate_input(input_filename: PosixPath) -> PosixPath:
    mutant_filename: PosixPath = PosixPath(f"inputs/{random.randint(0, 2**32-1)}.input")
    with open(mutant_filename, "wb") as ofile, open(input_filename, "rb") as ifile:
        b: bytes = ifile.read()

        mutators: List[Callable[[bytes], bytes]] = [byte_insert]
        if len(b) > 0:
            mutators.append(byte_change)
        if len(b) > 1:
            mutators.append(byte_delete)
        if HAS_GRAMMAR:
            try:
                m: Optional[re.Match] = re.match(grammar_re, str(b, "UTF-8"))
                if m is not None:
                    mutators.append(functools.partial(grammar_mutate, m))
            except UnicodeDecodeError:
                pass

        ofile.write(random.choice(mutators)(b))

    return mutant_filename


def parse_trace_file(trace_file: io.TextIOWrapper) -> Dict[int, int]:
    result: Dict[int, int] = {}
    for line in trace_file.readlines():
        edge, count = map(int, line.strip().split(":"))
        result[edge] = count
    return result


def get_trace_length(trace_file: io.TextIOWrapper) -> int:
    return sum(c for e, c in parse_trace_file(trace_file).items())


def get_trace_edge_set(trace_file: io.TextIOWrapper) -> FrozenSet[int]:
    return frozenset(e for e, c in parse_trace_file(trace_file).items())


def get_trace_filename(executable: PosixPath, input_file: PosixPath) -> PosixPath:
    return TRACE_DIR.joinpath(PosixPath(f"{input_file.name}.{executable.name}.trace"))


def make_command_line(target_config: TargetConfig, current_input: PosixPath) -> List[str]:
    command_line: List[str] = []
    if target_config.needs_tracing:
        if target_config.needs_python_afl:
            command_line.append("py-afl-showmap")
        else:
            command_line.append("afl-showmap")
        if target_config.needs_qemu:  # Enable QEMU mode, if necessary
            command_line.append("-Q")
        command_line.append("-e")  # Only care about edge coverage; ignore hit counts
        command_line += [
            "-o",
            str(get_trace_filename(target_config.executable, current_input).resolve()),
        ]
        command_line += ["-t", str(TIMEOUT_TIME)]
        command_line.append("--")
        if target_config.needs_python_afl:
            command_line.append("python3")

    command_line.append(str(target_config.executable.resolve()))
    command_line += target_config.cli_args

    return command_line


def run_executables(
    current_input: PosixPath,
) -> Tuple[fingerprint_t, Tuple[int, ...], Tuple[bytes, ...]]:
    traced_procs: List[subprocess.Popen] = []

    # We need these to extract exit statuses
    untraced_procs: List[subprocess.Popen] = []

    for target_config in TARGET_CONFIGS:
        command_line: List[str] = make_command_line(target_config, current_input)
        if target_config.needs_tracing:
            with open(current_input) as input_file:
                traced_procs.append(
                    subprocess.Popen(
                        command_line,
                        stdin=input_file,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        env=target_config.env,
                    )
                )
        with open(current_input) as input_file:
            untraced_command_line: List[str] = (
                command_line[command_line.index("--") + 1 :] if target_config.needs_tracing else command_line
            )
            untraced_procs.append(
                subprocess.Popen(
                    untraced_command_line,
                    stdin=input_file,
                    stdout=subprocess.PIPE if OUTPUT_DIFFERENTIALS_MATTER else subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=target_config.env,
                )
            )

    # Wait for the processes to exit
    for proc in itertools.chain(traced_procs, untraced_procs):
        proc.wait()

    # Extract their stdouts
    stdouts: List[bytes] = []
    for proc, target_config in zip(untraced_procs, TARGET_CONFIGS):
        stdout_bytes: bytes = proc.stdout.read() if proc.stdout is not None else b""
        if HAS_NORMALIZATION:
            stdout_bytes = normalize(stdout_bytes, target_config.encoding)
        stdouts.append(stdout_bytes)

    # Extract their traces
    l = []
    for c in TARGET_CONFIGS:
        if c.needs_tracing:
            with open(get_trace_filename(c.executable, current_input)) as trace_file:
                l.append(get_trace_edge_set(trace_file))
        else:
            l.append(frozenset())

    fingerprint = hash(tuple(l))

    statuses: Tuple[int, ...] = (
        tuple(proc.returncode for proc in untraced_procs)
        if EXIT_STATUSES_MATTER
        else tuple(proc.returncode != 0 for proc in untraced_procs)
    )
    return fingerprint, statuses, tuple(stdouts)


def main() -> None:
    if len(sys.argv) > 2:
        print(f"Usage: python3 {sys.argv[0]}", file=sys.stderr)
        sys.exit(1)

    input_queue: List[PosixPath] = SEED_INPUTS.copy()

    # One input `I` produces one trace per program being fuzzed.
    # Convert each trace to a (frozen)set of edges by deduplication.
    # Pack those sets together in a tuple and hash it.
    # This is a fingerprint of the programs' execution on the input `I`.
    # Keep these fingerprints in a set.
    # An input is worth mutation if its fingerprint is new.
    explored: Set[fingerprint_t] = set()

    generation: int = 0
    exit_status_differentials: List[PosixPath] = []
    output_differentials: List[PosixPath] = []
    try:
        with multiprocessing.Pool(processes=multiprocessing.cpu_count() // (len(TARGET_CONFIGS) * 2)) as pool:
            while len(input_queue) != 0:  # While there are still inputs to check,
                print(
                    color(
                        Color.green,
                        f"Starting generation {generation}. {len(input_queue)} inputs to try.",
                    )
                )
                # run the programs on the things in the input queue.
                fingerprints_and_statuses_and_stdouts = tqdm(
                    pool.imap(run_executables, input_queue), desc="Running targets", total=len(input_queue)
                )

                mutation_candidates: List[PosixPath] = []
                rejected_candidates: List[PosixPath] = []

                for current_input, (fingerprint, statuses, stdouts) in zip(
                    input_queue, fingerprints_and_statuses_and_stdouts
                ):
                    # If we found something new, mutate it and add its children to the input queue
                    # If we get one program to fail while another succeeds, then we're doing good.
                    if fingerprint not in explored:
                        explored.add(fingerprint)
                        status_set: Set[int] = set(statuses)
                        if len(status_set) != 1:
                            print(
                                color(
                                    Color.blue,
                                    f"Exit Status Differential: {str(current_input.resolve())}",
                                )
                            )
                            for i, status in enumerate(statuses):
                                print(
                                    color(
                                        Color.red if status else Color.blue,
                                        f"    Exit status {status}:\t{str(TARGET_CONFIGS[i].executable)}",
                                    )
                                )
                            exit_status_differentials.append(current_input)
                        elif status_set == {0} and len(set(stdouts)) != 1:
                            print(
                                color(
                                    Color.yellow,
                                    f"Output differential: {str(current_input.resolve())}",
                                )
                            )
                            for i, s in enumerate(stdouts):
                                print(
                                    color(
                                        Color.yellow,
                                        f"    {str(TARGET_CONFIGS[i].executable)} printed this:\n\t{s!r}",
                                    )
                                )
                            output_differentials.append(current_input)
                        else:
                            # We don't mutate exit_status_differentials, even if they're new
                            # print(color(Color.yellow, f"New coverage: {str(current_input.resolve())}"))
                            mutation_candidates.append(current_input)
                    else:
                        # print(color(Color.grey, f"No new coverage: {str(current_input.resolve())}"))
                        rejected_candidates.append(current_input)

                input_queue = []
                while mutation_candidates != [] and len(input_queue) < ROUGH_DESIRED_QUEUE_LEN:
                    for input_to_mutate in mutation_candidates:
                        input_queue.append(mutate_input(input_to_mutate))

                for reject in rejected_candidates:
                    if reject not in SEED_INPUTS:
                        os.remove(reject)

                print(
                    color(
                        Color.green,
                        f"End of generation {generation}.\n"
                        f"Output differentials:\t\t{len(output_differentials)}\n"
                        f"Exit status differentials:\t{len(exit_status_differentials)}\n"
                        f"Mutation candidates:\t\t{len(mutation_candidates)}",
                    )
                )

                fingerprints: List[fingerprint_t] = []
                proc_lists: List[subprocess.Popen] = []
                generation += 1
    except KeyboardInterrupt:
        pass

    if exit_status_differentials == output_differentials == []:
        print("No differentials found! Try increasing ROUGH_DESIRED_QUEUE_LEN.")
    else:
        if exit_status_differentials != []:
            print(f"Exit status differentials:")
            print("\n".join(str(f.resolve()) for f in exit_status_differentials))
        if output_differentials != []:
            print(f"Output differentials:")
            print("\n".join(str(f.resolve()) for f in output_differentials))


# For pretty printing
class Color(Enum):
    red = 0
    blue = 1
    green = 2
    yellow = 3
    grey = 4
    none = 5


def color(color: Color, s: str):
    COLOR_CODES = {
        Color.red: "\033[0;31m",
        Color.blue: "\033[0;34m",
        Color.green: "\033[0;32m",
        Color.yellow: "\033[0;33m",
        Color.grey: "\033[0;90m",
        Color.none: "\033[0m",
    }
    return COLOR_CODES[color] + s + COLOR_CODES[Color.none]


if __name__ == "__main__":
    main()
