#!/usr/bin/env python3
import targets.pyasn1.pyasn1_target as pyas
import targets.asn1crypto.asn1crypto_target as asncry
import os
import diff_fuzz
from config import TARGET_CONFIGS, ParseTree, compare_parse_trees
import itertools
from frozendict import frozendict
from typing import Tuple
import multiprocessing
from tqdm import tqdm
from base64 import b64decode
from json import decoder


def main():
    directory = "asn1corpus"
    fails: int = 0
    success: int = 0
    differences: int = 0
    input_queue: list[str] = []
    for filename in os.listdir(directory):
        input_queue.append(os.path.join(directory, filename))

    with multiprocessing.Pool(processes=os.cpu_count()) as pool:
        # run the programs on the things in the input queue.
        statuses_and_parse_trees = tqdm(
            pool.imap(executables_wrapper, input_queue),
            desc="Running targets",
            total=len(input_queue),
        )
        for statuses, parse_trees in statuses_and_parse_trees:
            if len(set(statuses)) == 1 and set(statuses) == {0}:
                if not all(
                    all(comp)
                    for comp in itertools.starmap(compare_parse_trees, itertools.combinations(parse_trees, 2))
                ):
                    differences += 1
                    print("---------------------------------------")
                    print(f"{filename}\n")
                    for i, tc in enumerate(TARGET_CONFIGS):
                        print(f"{tc.executable}:\n f{str_recursive(parse_trees[i].tree)}")
                else:
                    success += 1
            else:
                fails += 1

    print(f"Successes: {success}")
    print(f"Differences: {differences}")
    print(f"Failures: {fails}")


def executables_wrapper(
    input_file_path: str,
) -> Tuple[Tuple[int, ...], Tuple[ParseTree | None, ...]]:
    with open(input_file_path, "rb") as input_file:
        current_input: bytes = input_file.read()
        try:
            _, statuses, parse_trees = diff_fuzz.run_executables(current_input, disable_tracing=True)
        except decoder.JSONDecodeError as e:
            print(f"ERROR FILE: {input_file_path}")
            raise e

    return (statuses, parse_trees)


def str_recursive(to_convert: any) -> any:
    if isinstance(to_convert, list):
        return f"[{','.join(to_convert)}]"
    elif isinstance(to_convert, frozendict):
        dict_str = "{"
        for k in to_convert:
            dict_str += k + ":"
            if k == "value":
                dict_str += str_recursive(to_convert[k]) + ","
            else:
                dict_str += to_convert[k] + ","
        dict_str += "}"
        return dict_str
    try:
        return b64decode(str(to_convert)).decode("utf-8")
    except:
        return str(to_convert)


if __name__ == "__main__":
    main()
