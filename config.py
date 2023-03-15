#############################################################################################
# config.py
# This is the configuration file for diff_fuzz.py
# Add new targets by adding new entries to TARGET_CONFIGS.
#############################################################################################

from pathlib import PosixPath
from typing import NamedTuple, List, Dict, Optional
import os

# The directory where the seed inputs are
# The seeds are the files from which all the fuzzing inputs are produced,
# so it's important that the seeds are a decently representative sample
# of the inputs accepted by the targets.
SEED_DIR: PosixPath = PosixPath("./seeds")

# Where program traces end up
TRACE_DIR: PosixPath = PosixPath("./traces")

# Time in milliseconds given to each process
TIMEOUT_TIME: int = 100000

# Set this to false if you only care about exit status differentials
# (i.e. the programs you're testing aren't expected to have identical output on stdout)
OUTPUT_DIFFERENTIALS_MATTER: bool = True

# Roughly how many processes to allow in a generation (within a factor of 2)
ROUGH_DESIRED_QUEUE_LEN: int = 1000

# AFL++ and AFL differ a little about what goes on stdout and what goes on stderr.
# Set this flag if you're using AFL++ so that can be handled correctly.
USES_AFLPLUSPLUS: bool = True

class TargetConfig(NamedTuple):
    executable: PosixPath  # The path to this target's executable
    cli_args: List[str]  # The CLI arguments this target needs
    needs_qemu: bool  # Whether this executable needs to run in QEMU mode (is a binary that wasn't compiled with AFL instrumentation)
    needs_python_afl: bool  # Whether this executable needs to run with python-afl (is a python script)
    env: Dict[str, str]  # The environment variables to pass to the executable


# Configuration for each fuzzing target
TARGET_CONFIGS: List[TargetConfig] = [
    TargetConfig(
        executable=PosixPath("./targets/baby-cpp/baby-cpp"),
        cli_args=[],
        needs_qemu=False,
        needs_python_afl=False,
        env=dict(os.environ),
    ),
    TargetConfig(
        executable=PosixPath("./targets/baby-c/baby-c"),
        cli_args=[],
        needs_qemu=True,
        needs_python_afl=False,
        env=dict(os.environ),
    ),
]
