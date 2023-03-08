# `diff_fuzz.py`

`diff_fuzz.py` is a coverage-guided differential fuzzer written in Python.
Its configuration lives in `config.py`.

The tracing is implemented with `afl-showmap`, so targets must be able to be traced by AFL, and `afl-showmap` must be available on your system. The easiest way to do this is to install AFL or AFL++ from your package manager.

Python targets can be instrumented using [`python-afl`](https://github.com/jwilk/python-afl).
Binary tracing is supported through QEMU.

A toy example is included.
To run it:
```sh
cd targets/baby-c
make
cd ../baby-cpp
make
cd ../..
python diff_fuzz.py
```
