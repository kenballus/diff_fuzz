#############################################################################################
# config.py
# This is the configuration file for diff_fuzz.py
# Add new targets by adding new entries to TARGET_CONFIGS.
#############################################################################################

from pathlib import PosixPath
from typing import List, Dict, Tuple
from dataclasses import dataclass, field
from frozendict import frozendict
from frozenlist import FrozenList
import functools
from os import environ

# The directory where the seed inputs are
# The seeds are the files from which all the fuzzing inputs are produced,
# so it's important that the seeds are a decently representative sample
# of the inputs accepted by the targets.
SEED_DIR: PosixPath = PosixPath("./seeds")

# The directory where the findings go when the fuzzer run finishes.
RESULTS_DIR: PosixPath = PosixPath("./results")

# Time in milliseconds given to each process
TIMEOUT_TIME: int = 10000

# Set this to false if you only care about exit status differentials
# (i.e. the programs you're testing aren't expected to have identical output on stdout)
DETECT_OUTPUT_DIFFERENTIALS: bool = True

# Set this to True if you want to use grammar mutations.
# (Requires a grammar.py with the appropriate interface)
USE_GRAMMAR_MUTATIONS: bool = False

# When this is True, a differential is registered if two targets exit with different status codes.
# When it's False, a differential is registered only when one target exits with status 0 and another
# exits with nonzero status.
DIFFERENTIATE_NONZERO_EXIT_STATUSES: bool = False

# Roughly how many processes to allow in a generation (within a factor of 2)
ROUGH_DESIRED_QUEUE_LEN: int = 100

# The number of bytes deleted at a time in the minimization loop
# The default choice was selected because of UTF-8.
DELETION_LENGTHS: List[int] = [4, 3, 2, 1]


# This is the parse tree class for your programs' output.
# If OUTPUT_DIFFERENTIALS_MATTER is set to False, then you can leave this as it is.
# Otherwise, it should have a `bytes` field for each field in your programs'
# output JSON.
@dataclass(frozen=True)
class ParseTree:
    tree: frozendict[str, any]

def create_parse_tree(*args, **kwargs) -> ParseTree:
    return ParseTree(freeze(kwargs['tree']))

def freeze(to_freeze: any) -> any:
    if type(to_freeze) == list:
        fl = FrozenList()
        for v in to_freeze:
            fl.append(freeze(v))
        fl.freeze()
        return fl
    elif type(to_freeze) == dict:
        for k in to_freeze:
            to_freeze[k] = freeze(to_freeze[k])
        return frozendict(to_freeze)
    return to_freeze

# This is the comparison operation on parse trees.
# During minimization, the result of the function is preserved.
# If your programs' output is expected to match completely, then leave this as-is.
# Otherwise, rewrite it to implement an equivalence relation between your parse trees.
def compare_parse_trees(t1: ParseTree, t2: ParseTree) -> Tuple[bool, ...]:
    return (t1.tree==t2.tree,)

def build_comparison(d1: dict[str, any], d2: dict[str, any]) -> Tuple[bool, ...]:
    if d1['tag'] != d2['tag']:
        return (False,)
    if d1['tag'] == 16 or d1['tag'] == 17: # Sequence
        list_comparison: tuple[bool, ...] = tuple()
        for item1, item2 in zip(d1['value'], d2['value']):
            list_comparison += build_comparison(item1, item2)
            if not list_comparison[len(list_comparison) - 1]:
                return list_comparison
        if len(d1['value']) != len(d2['value']):
            list_comparison += (False,)
        return list_comparison
    # elif d1['tag'] == 17: # Set TODO
    #     pass
    else:
        return (d1['value']==d2['value'],)
        

@dataclass(frozen=True)
class TargetConfig:
    # The path to this target's executable
    executable: PosixPath
    # The CLI arguments this target needs
    cli_args: List[str] = field(default_factory=list)
    # Whether this executable should be traced.
    # (turning off tracing is useful for untraceable
    #  oracle targets, such as those written in
    #  unsupported languages)
    needs_tracing: bool = True
    # Whether this executable needs to run in QEMU mode
    # (should be True when target is not instrumented for AFL)
    needs_qemu: bool = False
    # Whether this executable needs to run with python-afl (is a python script)
    needs_python_afl: bool = False
    # The environment variables to pass to the executable
    env: Dict[str, str] = field(default_factory=lambda: dict(environ))


# Configuration for each fuzzing target
TARGET_CONFIGS: List[TargetConfig] = [
    TargetConfig(
        executable=PosixPath("./targets/pyasn1/pyasn1_target.py"),
        needs_python_afl=True,
    ),
    TargetConfig(
        executable=PosixPath("./targets/asn1crypto/asn1crypto_target.py"),
        needs_python_afl=True,
    ),
    # TargetConfig(
    #     executable=PosixPath("./targets/baby-cpp/baby-cpp"),
    # ),
    # TargetConfig(
    #     executable=PosixPath("./targets/baby-c/baby-c"),
    #     needs_qemu=True,
    # ),
    # TargetConfig(
    #     executable=PosixPath("./targets/baby-py/baby.py"),
    #     needs_python_afl=True,
    # ),
]
