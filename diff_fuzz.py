#############################################################################################
# diff_fuzz.py
# This is a wrapper around afl-showmap that does differential fuzzing a la
#   https://github.com/nezha-dt/nezha, but much slower.
# Fuzzing targets are configured in `config.py`.
# Grammar is optionally specified in `grammar.py`.
#############################################################################################

import sys
import subprocess
import dataclasses
import multiprocessing
import random
import itertools
import os
import json
import functools
import uuid
import shutil
import base64
import time
from pathlib import PosixPath
from typing import Callable


from tqdm import tqdm  # type: ignore

from config import (
    compare_parse_trees,
    get_replacement_byte,
    ParseTree,
    TargetConfig,
    TIMEOUT_TIME,
    TARGET_CONFIGS,
    ROUGH_DESIRED_QUEUE_LEN,
    SEED_DIR,
    DETECT_OUTPUT_DIFFERENTIALS,
    DIFFERENTIATE_NONZERO_EXIT_STATUSES,
    DELETION_LENGTHS,
    RESULTS_DIR,
    REPORTS_DIR,
    USE_GRAMMAR_MUTATIONS,
)

if USE_GRAMMAR_MUTATIONS:
    try:
        from grammar import GRAMMAR_MUTATORS  # type: ignore[import]
    except ModuleNotFoundError:
        print(
            "`grammar.py` not found. Either make one or set USE_GRAMMAR_MUTATIONS to False", file=sys.stderr
        )
        sys.exit(1)

assert SEED_DIR.is_dir()
SEED_INPUTS: list[PosixPath] = list(map(lambda s: SEED_DIR.joinpath(PosixPath(s)), os.listdir(SEED_DIR)))

assert RESULTS_DIR.is_dir()
assert REPORTS_DIR.is_dir()

assert all(map(lambda tc: tc.executable.exists(), TARGET_CONFIGS))

fingerprint_t = tuple[frozenset[int], ...]

json_t = None | bool | str | int | float | dict[str, "json_t"] | list["json_t"]


def byte_replace(b: bytes) -> bytes:
    if len(b) == 0:
        raise ValueError("Mutation precondition didn't hold.")
    index: int = random.randint(0, len(b) - 1)
    return b[:index] + bytes([random.randint(0, 255)]) + b[index + 1 :]


def byte_insert(b: bytes) -> bytes:
    index: int = random.randint(0, len(b))
    return b[:index] + bytes([random.randint(0, 255)]) + b[index:]


def byte_delete(b: bytes) -> bytes:
    if len(b) <= 1:
        raise ValueError("Mutation precondition didn't hold.")
    index: int = random.randint(0, len(b) - 1)
    return b[:index] + b[index + 1 :]


MUTATORS: list[Callable[[bytes], bytes]] = [byte_replace, byte_insert, byte_delete] + (
    GRAMMAR_MUTATORS if USE_GRAMMAR_MUTATIONS else []
)


def mutate(b: bytes) -> bytes:
    mutators: list[Callable[[bytes], bytes]] = MUTATORS.copy()
    while len(mutators) != 0:
        try:
            mutator: Callable[[bytes], bytes] = random.choice(mutators)
            return mutator(b)
        except ValueError:
            mutators.remove(mutator)
    print("Input {b!r} cannot be mutated.", file=sys.stderr)
    sys.exit(1)


def parse_tracer_output(tracer_output: bytes) -> frozenset[int]:
    result: set[int] = set()
    for line in tracer_output.split(b"\n"):
        try:
            edge, _ = map(int, line.strip().split(b":"))
            result.add(edge)
        except ValueError:
            pass
    return frozenset(result)


def make_command_line(tc: TargetConfig) -> list[str]:
    """
    Make the afl-showmap command line for this target config.
    If input_dir and output_dir are None, then read from stdin and write to stdout.
    """
    command_line: list[str] = []
    if tc.needs_tracing:
        if tc.needs_python_afl:
            command_line.append("py-afl-showmap")
        else:
            command_line.append("afl-showmap")
            if tc.needs_qemu:  # Enable QEMU mode, if necessary
                command_line.append("-Q")
        command_line.append("-q")  # Don't care about traced program stdout
        command_line.append("-e")  # Only care about edge coverage; ignore hit counts
        command_line += ["-o", "/dev/stdout"]

        command_line += ["-t", str(TIMEOUT_TIME)]
        command_line.append("--")

    command_line.append(str(tc.executable.resolve()))
    command_line += tc.cli_args

    return command_line


def minimize_differential(bug_inducing_input: bytes) -> tuple[bytes, fingerprint_t]:
    orig_statuses, orig_parse_trees, orig_fingerprint = run_targets(bug_inducing_input)

    needs_parse_tree_comparison: bool = len(set(orig_statuses)) == 1

    orig_parse_tree_comparisons: list[tuple[bool, ...]] = (
        list(itertools.starmap(compare_parse_trees, itertools.combinations(orig_parse_trees, 2)))
        if needs_parse_tree_comparison
        else [(True,)]
    )

    result_input: bytes = bug_inducing_input
    result_fingerprint: fingerprint_t = orig_fingerprint

    for deletion_length in DELETION_LENGTHS:
        i: int = len(result_input) - deletion_length
        while i >= 0:
            reduced_form: bytes = result_input[:i] + result_input[i + deletion_length :]
            if reduced_form == b"":
                i -= 1
                continue
            new_statuses, new_parse_trees, new_fingerprint = run_targets(reduced_form)
            if (
                new_statuses == orig_statuses
                and (
                    list(itertools.starmap(compare_parse_trees, itertools.combinations(new_parse_trees, 2)))
                    if needs_parse_tree_comparison
                    else [(True,)]
                )
                == orig_parse_tree_comparisons
            ):
                result_input = reduced_form
                result_fingerprint = new_fingerprint
                i -= deletion_length
            else:
                i -= 1

    # This will break if a replacement changes the length of result.
    for i, c in enumerate(result_input):
        replacement_byte: bytes = get_replacement_byte(c)
        if replacement_byte == b"":  # No replacement can be made
            continue
        substituted_form: bytes = result_input[:i] + replacement_byte + result_input[i + 1 :]
        new_statuses, new_parse_trees, new_fingerprint = run_targets(substituted_form)
        if (
            new_statuses == orig_statuses
            and (
                list(itertools.starmap(compare_parse_trees, itertools.combinations(new_parse_trees, 2)))
                if needs_parse_tree_comparison
                else [(True,)]
            )
            == orig_parse_tree_comparisons
        ):
            result_input = substituted_form
            result_fingerprint = new_fingerprint

    return result_input, result_fingerprint


@functools.cache
def run_targets(the_input: bytes) -> tuple[tuple[int, ...], tuple[ParseTree | None, ...], fingerprint_t]:
    """
    This function needs a better name.
    This runs the targets on an input, and returns a (exit_statuses, parse_trees) pair.
    (A call to this function makes one process for each configured target)
    """
    procs: list[subprocess.Popen] = []

    for tc in TARGET_CONFIGS:
        command_line: list[str] = make_command_line(tc)

        proc: subprocess.Popen = subprocess.Popen(
            command_line,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE if DETECT_OUTPUT_DIFFERENTIALS else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=tc.env,
        )
        assert proc.stdin is not None
        proc.stdin.write(the_input)
        proc.stdin.close()
        procs.append(proc)

    # Wait for the processes to exit
    for proc in procs:
        if proc is not None:
            proc.wait()

    # Extract the exit statuses
    statuses: tuple[int, ...] = tuple(proc.returncode for proc in procs)
    if not DIFFERENTIATE_NONZERO_EXIT_STATUSES:
        statuses = tuple(map(lambda i: int(bool(i)), statuses))

    # TODO: Make seperate trace output and parse trees
    # Extract the parse trees
    parse_trees: tuple[ParseTree | None, ...] = tuple(
        ParseTree(**{k: base64.b64decode(v) for k, v in json.loads(proc.stdout.read()).items()})
        if proc.stdout is not None and status == 0
        else None
        for proc, status in zip(procs, statuses)
    )

    # Extract the traces
    fingerprint: list[frozenset[int]] = []
    for tc in TARGET_CONFIGS:
        if tc.needs_tracing:
            # TODO: Read the trace into a fingerprint
            fingerprint.append(frozenset())
        else:
            fingerprint.append(frozenset())

    return statuses, parse_trees, tuple(fingerprint)


# Data class for holding information about how many cumulative unique edges of each parser were found in each generation and at what time.
# Stored in JSON in the coverage list which has a list for each parser, these lists consist of JSON objects for each generation which record generation, time, and
# number of unique edges uncovered in that parser up to that generation.
@dataclasses.dataclass
class EdgeCountSnapshot:
    edge_count: int
    time: float
    generation: int


@dataclasses.dataclass
class Differential:
    differential: bytes
    time_found: float
    generation_found: int


def fuzz() -> tuple[list[Differential], dict[str, list[EdgeCountSnapshot]]]:
    start_time: float = time.time()
    differentials_with_info: list[Differential] = []
    coverage_info: dict[str, list[EdgeCountSnapshot]] = {tc.name: [] for tc in TARGET_CONFIGS}
    num_cpus = os.cpu_count()
    assert num_cpus is not None

    # Since each parser run makes len(TARGET_CONFIGS) processes,
    # we should have about (num_cpus / len(TARGET_CONFIGS)) workers.
    # That said, experiments show that num_cpus is still better for some reason.
    num_workers: int = num_cpus

    input_queue: list[bytes] = []
    for seed_input in SEED_INPUTS:
        with open(seed_input, "rb") as f:
            input_queue.append(f.read())

    # One input `I` produces one trace per program being fuzzed.
    # Convert each trace to a frozenset of edges by deduplication.
    # Pack those sets together in a tuple.
    # This is a fingerprint of the programs' execution on the input `I`.
    # Keep these fingerprints in a set.
    # An input is worth mutation if its fingerprint is new.
    seen_fingerprints: set[fingerprint_t] = set()

    seen_edges: dict[str, set[int]] = {tc.name: set() for tc in TARGET_CONFIGS}

    # This is the set of fingerprints that correspond with minimized differentials.
    # Whenever we minimize a differential into an input with a fingerprint not in this set,
    # we report it and add it to this set.
    minimized_fingerprints: set[fingerprint_t] = set()

    generation: int = 0

    try:
        while len(input_queue) != 0:  # While there are still inputs to check,
            print(f"Starting generation {generation}.", file=sys.stderr)
            mutation_candidates: list[bytes] = []
            differentials: list[bytes] = []

            # Re-run all the targets, this time collecting stdouts and statuses
            with multiprocessing.Pool(processes=num_workers) as pool:
                statuses_parse_trees_fingerprint: list[
                    tuple[tuple[int, ...], tuple[ParseTree | None, ...], fingerprint_t]
                ] = list(
                    tqdm(
                        pool.imap(run_targets, input_queue),
                        desc="Running targets...",
                        total=len(input_queue),
                    )
                )

            # Check for differentials and new coverage
            for current_input, (statuses, parse_trees, fingerprint) in zip(
                input_queue, statuses_parse_trees_fingerprint
            ):
                if fingerprint not in seen_fingerprints:
                    seen_fingerprints.add(fingerprint)
                    status_set: set[int] = set(statuses)
                    if (len(status_set) != 1) or (
                        DETECT_OUTPUT_DIFFERENTIALS
                        and status_set == {0}
                        and any(
                            False in cmp_vector
                            for cmp_vector in itertools.starmap(
                                compare_parse_trees, itertools.combinations(parse_trees, 2)
                            )
                        )
                    ):
                        differentials.append(current_input)
                    else:
                        mutation_candidates.append(current_input)
                    # Record new edges
                    for tc, new_edges in zip(TARGET_CONFIGS, fingerprint):
                        seen_edges[tc.name].update(new_edges)

            for tc in TARGET_CONFIGS:
                coverage_info[tc.name].append(
                    EdgeCountSnapshot(len(seen_edges[tc.name]), time.time() - start_time, generation)
                )

            # Minimize differentials
            with multiprocessing.Pool(processes=num_workers) as pool:
                minimized_inputs: list[tuple[bytes, fingerprint_t]] = list(
                    tqdm(
                        pool.imap(minimize_differential, differentials),
                        desc="Minimizing differentials...",
                        total=len(differentials),
                    )
                )
                print("done!", file=sys.stderr)
                for minimized_input, minimized_fingerprint in minimized_inputs:
                    if minimized_fingerprint not in minimized_fingerprints:
                        differentials_with_info.append(
                            Differential(minimized_input, time.time() - start_time, generation)
                        )
                        minimized_fingerprints.add(minimized_fingerprint)

            input_queue.clear()
            while len(mutation_candidates) != 0 and len(input_queue) < ROUGH_DESIRED_QUEUE_LEN:
                input_queue += list(map(mutate, mutation_candidates))

            print(
                f"End of generation {generation}.\n"
                + f"Differentials:\t\t{len(differentials_with_info)}\n"
                + f"Mutation candidates:\t{len(mutation_candidates)}\n"
                + f"Coverage:\t\t\t{tuple(len(x) for x in seen_edges.values())}",
                file=sys.stderr,
            )
            generation += 1
    except KeyboardInterrupt:
        pass

    return differentials_with_info, coverage_info


def main() -> None:
    if len(sys.argv) > 2:
        print(f"Usage: python3 {sys.argv[0]} run_folder", file=sys.stderr)
        sys.exit(1)

    run_id: str = sys.argv[1] if len(sys.argv) >= 2 else str(uuid.uuid4())
    if os.path.exists(RESULTS_DIR.joinpath(run_id)):
        print("Results folder already exists. Overriding.", file=sys.stderr)
        shutil.rmtree(RESULTS_DIR.joinpath(run_id))

    differentials_with_info, coverage_info = fuzz()

    run_results_dir = RESULTS_DIR.joinpath(run_id)
    os.mkdir(run_results_dir)
    for final_diff_with_info in differentials_with_info:
        final_differential: bytes = final_diff_with_info.differential
        result_file_path = run_results_dir.joinpath(str(hash(final_differential)))
        with open(result_file_path, "wb") as result_file:
            result_file.write(final_differential)
            print(
                f"Differential: {str(final_differential)[2:-1]:20} Path: {str(result_file_path)}",
                file=sys.stderr,
            )

    coverage_output: json_t = {
        tc.name: [
            {
                "edges": edge_datapoint.edge_count,
                "time": edge_datapoint.time,
                "generation": edge_datapoint.generation,
            }
            for edge_datapoint in coverage_info[tc.name]
        ]
        for tc in TARGET_CONFIGS
    }
    differentials_output: json_t = [
        {
            "differential": base64.b64encode(diff_with_info.differential).decode("ascii"),
            "path": str(run_results_dir.joinpath(str(hash(diff_with_info.differential))).resolve()),
            "time": diff_with_info.time_found,
            "generation": diff_with_info.generation_found,
        }
        for diff_with_info in differentials_with_info
    ]
    output: json_t = {
        "uuid": run_id,
        "coverage": coverage_output,
        "differentials": differentials_output,
    }
    with open(REPORTS_DIR.joinpath(run_id).with_suffix(".json"), "w", encoding="latin-1") as report_file:
        report_file.write(json.dumps(output))

    print(run_id)


if __name__ == "__main__":
    main()
