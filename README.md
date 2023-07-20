# url\_differential\_fuzzing
This is basically a wrapper around `afl-showmap++` that enables differential fuzzing of URL parsers. Nothing about this work is specific to URL, and I plan to expand it to other protocols in the future.

# Installation
To install and set up the fuzzing environment, run
```bash
./setup.sh
```
(This will not install AFL++ or python3 for you. You'll need to get those yourself.)

# Running it
To start fuzzing the default targets with the default configuration, run
```bash
make
```
