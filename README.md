# `diff_fuzz.py`
`diff_fuzz.py` is a coverage-guided differential fuzzer written in Python.
Each configuration option is set and documented in `config.py`.

Tracing is implemented with `afl-showmap`, so `afl-showmap` must be available on your system.
The easiest way to do this is to install AFL or AFL++ from your package manager.

Python targets can be instrumented for tracing using [`python-afl`](https://github.com/jwilk/python-afl).
Binary tracing is supported through QEMU.

A toy example is included. The default `config.py` is set up for this example.
To run it:
```sh
cd targets/baby-c
make
cd ../baby-cpp
make
cd ../..
make
```

These two programs each try to read a byte from stdin.
Both exit with status 255 when stdin has no bytes available for consumption.
`baby-c` exits with status 1 when its byte (signed) is greater than 1.
`baby-cpp` exits with status 1 when its byte (unsigned) is greater than 1.
Both exit with status 0 in all other cases.
Of course, these two programs will exhibit differential behavior when the byte they read has its most significant bit set.
The fuzzer will probably discover such an input in generation 1.

`baby-c` is compiled without AFL instrumentation in order to demonstrate QEMU mode.

# Grammar-Based Fuzzing
To use grammar-based mutation, you need to supply a file `grammar.py` with the following symbols defined:
- `grammar_re`:   A regular expression that describes the grammar.
- `grammar_dict`: A dictionary that labels the named group rules in `grammar_re` with their names as strings.
- `generate_random_matching_input`: A function that takes a regular expression, and returns a string matching that expression. (Hint: try `hypothesis.strategies.from_regex`)

# Acknowledgements:
This work made possible by the DARPA GAPS program and the GAPS teams at GE Research and Dartmouth College.
