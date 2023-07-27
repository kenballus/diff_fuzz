#############################################################################################
# diff_fuzz.py
# This is a wrapper around afl-showmap that does differential fuzzing a la
#   https://github.com/nezha-dt/nezha, but much slower.
# Fuzzing targets are configured in `config.py`.
# Grammar is optionally specified in `grammar.py`.
#############################################################################################

import sys
import dataclasses
import multiprocessing
import random
import itertools
import os
import json
import uuid
import shutil
import base64
import time
import socket
from pathlib import PosixPath
from typing import Callable

import docker  # type: ignore
from tqdm import tqdm  # type: ignore

from config import (
    compare_parse_trees,
    get_replacement_byte,
    ParseTree,
    TIMEOUT_TIME,
    TARGET_CONFIGS,
    ROUGH_DESIRED_QUEUE_LEN,
    SEED_DIR,
    DETECT_OUTPUT_DIFFERENTIALS,
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


def send_input_all_targets(
    input_to_send: bytes,
) -> tuple[tuple[int, ...], tuple[ParseTree | None, ...], fingerprint_t]:
    statuses: list[int] = []
    parse_trees: list[ParseTree | None] = []
    fingerprint: list[frozenset[int]] = []
    for tc in TARGET_CONFIGS:
        status, parse_tree, edge_set = send_input(input_to_send, tc.ip, tc.port)
        statuses.append(status)
        parse_trees.append(parse_tree)
        fingerprint.append(edge_set)
    return (tuple(statuses), tuple(parse_trees), tuple(fingerprint))


def minimize_differential(bug_inducing_input: bytes) -> tuple[bytes, fingerprint_t]:
    orig_statuses, orig_parse_trees, orig_fingerprint = send_input_all_targets(bug_inducing_input)

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
            new_statuses, new_parse_trees, new_fingerprint = send_input_all_targets(reduced_form)
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
        new_statuses, new_parse_trees, new_fingerprint = send_input_all_targets(reduced_form)
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


def send_input(input_to_send: bytes, ip: str, port: int) -> tuple[int, ParseTree | None, frozenset[int]]:
    sock = socket.socket()
    sock.connect((ip, port))
    sock.sendall(input_to_send)
    sock.settimeout(TIMEOUT_TIME / 1000)
    result = b""
    try:
        while True:
            stuff = sock.recv(65536)
            if stuff == b"":
                break
            result = result + stuff
    except TimeoutError:
        pass
    if result == b"":
        return (1, None, frozenset(set()))

    # Extract the parse trees
    parse_tree: ParseTree = ParseTree(result)  # TODO: Do parse Trees for HTTP

    edges = set(random.randint(0, 100) for _ in range(10))  # TODO: Remove this
    return (0, parse_tree, frozenset(edges))


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

    # Make sure all IPs are set
    containers = docker.from_env().containers.list()
    for tc in TARGET_CONFIGS:
        if tc.ip == "":
            for container in containers:
                if container.name == tc.docker_name:
                    tc.ip = container.attrs["NetworkSettings"]["IPAddress"]
                    break
            else:
                raise NameError(f"Docker container {tc.docker_name} not found!")

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

            run_results: list[list[tuple[int, ParseTree | None, frozenset[int]]]] = []
            # Run all the targets
            for tc in TARGET_CONFIGS:
                with multiprocessing.Pool(processes=min(num_workers, tc.max_threads)) as pool:
                    complete_queue: list[tuple[bytes, str, int]] = list(
                        (i, tc.ip, tc.port) for i in input_queue
                    )
                    run_results.append(
                        list(
                            tqdm(
                                pool.starmap(send_input, complete_queue),
                                desc=f"Running targets on {tc.name}...",
                                total=len(input_queue),
                            )
                        )
                    )

            statuses_parse_trees_fingerprint: list[
                tuple[tuple[int, ...], tuple[ParseTree | None, ...], fingerprint_t]
            ] = []

            for idx in range(len(input_queue)):
                reorg_states: list[int] = []
                reorg_parse_trees: list[ParseTree | None] = []
                reorg_edge_sets: list[frozenset[int]] = []
                for tc_results in run_results:
                    reorg_states.append(tc_results[idx][0])
                    reorg_parse_trees.append(tc_results[idx][1])
                    reorg_edge_sets.append(tc_results[idx][2])
                statuses_parse_trees_fingerprint.append(
                    (tuple(reorg_states), tuple(reorg_parse_trees), tuple(reorg_edge_sets))
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
            # TODO: Cap threads to not overwhelm server or restructure
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
