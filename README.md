# `diff_fuzz.py`
`diff_fuzz.py` is a coverage-guided differential fuzzer written in Python.

# Installation
To install and set up the fuzzing environment, run
```bash
./setup.sh
```
(This will not install AFL++ or python3 for you. You'll need to get those yourself.)

### Binary Fuzzing
If you want to fuzz binary targets without instrumentation, you'll need to use a build of AFL(++) with QEMU support enabled.

### Python Fuzzing
If you want to fuzz Python programs, you'll need to have [`python-afl`](https://github.com/jwilk/python-afl) installed.
Note that `py-afl-showmap` defaults to using whichever AFL installation is first in your `PATH`, so if you have both AFL and AFL++ installed, you might end up with weird bugs.
The easiest thing to do is ensure that the AFL installation that you want to use comes first in your `PATH`.

# Configuration
Each configuration option is set and documented in `config.py`.

# Running
A testing example is included. The default `config.py` is set up for this example.
To run it:
```bash
make
```

There are two programs targeted in `config.py`; `baby-c` and `baby-cpp`.
These two programs each try to read a byte from stdin.
Both exit with status 255 when stdin has no bytes available for consumption.
`baby-c` exits with status 1 when its byte (signed) is greater than 1.
`baby-cpp` exits with status 1 when its byte (unsigned) is greater than 1.
Both exit with status 0 in all other cases.
Of course, these two programs will exhibit differential behavior when the byte they read has its most significant bit set.
The fuzzer will probably discover such an input in generation 1.

`baby-c` is compiled without AFL instrumentation in order to demonstrate QEMU mode.

Also included is `baby-py`, which is a target demonstrating Python instrumentation.
Its behavior differs from the other two targets in a few ways, most notably that it requires that it reads 1 UTF-8 character, not 1 byte.

# Interpreting Output

## Results

At the end of a run of the fuzzer, you should see several outputs on stderr that look something like this:
```
Differential: \xbe                 Path: results/9c2b1094-dd60-4ba0-b761-cea85e109898/7839048121533453113
```
This indicates that the generated input, displayed as `\xbe` in character-escaped ASCII causes two of targets to either have different stdouts or different exit statuses.
In an actual fuzzing run, you would then inspect it to determine the cause of the differential behavior.
The input is also saved in its byte form in the file `results/9c2b1094-dd60-4ba0-b761-cea85e109898/7839048121533453113`

## UUID (Universal Unique Identifier)

At the end of a run of the fuzzer you will see one output on stdout that looks something like this:
```
94ee5bed-0459-422b-a025-e6ce36efc8cd
```
This is the run's UUID. There will be a directory of this name the results directory and a file of this name in the reports directory. The UUID directory in the results directory has a file for each differential found which contain inputs in bytes that result in that differential. The UUID file in the reports directory is a JSON file which has information about the run.

## Generation Statistics

At the end of each generation in the fuzzer you will see output on stderr that looks something like this:
```
End of generation 3.
Differentials:          2
Mutation candidates:    0
Coverage:                       (3, 23, 28)
```
- `Differentials` is the total number of differentials found by this run of the fuzzer by the end of this generation.
- `Mutation Candidates` is the number of generated inputs in this generation that were interesting enough such that they can be used as the basis for further mutation.
- `Coverage` is the number of unique edges hit by this run of fuzzer for each target by the end of this generation.

# Grammar-Based Fuzzing
To use grammar-based mutation, you need to supply a file `grammar.py` with the following symbol defined:
- `GRAMMAR_MUTATORS`:   A list of functions which take bytes and apply a mutation to those bytes.
    - We suggest that the mutators should not introduce new bytes which are further from each other than the deletion lengths specified in the config file. Doing so will increase the chance that bugs are misclassfied during minimization.
    - ```python
      GRAMMAR_MUTATORS: list[Callable[[bytes], bytes]] = [grammar_delete, grammar_insert, grammar_replace]
      ```

# Acknowledgements:
This work made possible by the DARPA GAPS program and the GAPS teams at GE Research and Dartmouth College.
