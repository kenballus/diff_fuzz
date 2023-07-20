## Benchmarking Instructions

## Set-Up

The benchmarking module has to be setup with appropriate empty folders. To do this you can run `make` or run `make benchmarking` to only get the folders needed for benchmarking.

## Benchmarking Queues

Before tests can be run the user must first create a benchmarking queue file.

Tests can be added to a queue as follows:

```$name,$commit_hash,$timeout,[configfile]```

Each test will be run on `commit_hash` with config `configfile`.

`configfile` is optional and must correspond to the path of a config file which is not the currently enabled config file in the main directory.

If no config file is specified then the test will be run on the current config file in the main directory.

Each test will be forcefully ended after `timeout` seconds have elapsed or will run out of mutation candidates.

Complete Benchmarking Queue File Example:

```
Test A,043f804572d88cfd7be1dc7247bef28d875b0d60,30,/home/user1/url_differential_fuzzing/benchmarking/bench_configs/alt_config.py
Test B,043f804572d88cfd7be1dc7247bef28d875b0d60,30
Test C,b7aa710177b48a680e97d9851b34bcab366626cf,30,benchmarking/bench_configs/alt_config.py
```

## How to run

First ensure that there are no uncommited changes in git.

Run `python analyze.py [--bug-count] [--edge-count] [--bug-overlap] name_of_analysis queue_file`.

`name_of_analysis` will be the label for the final analysis graphs.

`queue_file` should be a completed benchmarking queue file that contains all the tests you want to compare.

It is suggested you keep benchmarking queue files in the queues directory but they can be kept anywhere.

`[--bug-count] [--edge-count] [--bug-overlap]` are optional flags that determine what type of analyses are done on the runs. These flags are detailed in the output section.

At least one of these flags must be enabled to do any analysis.

## Output

Analysis results will be saved in the analyses directory in a folder named by uuid.

The path to the analysis directory will be printed to stdout after the program runs.

Bugs are classified according to the current config in the main directory.

### Bug Graph Analysis, `[--bug-count]`

Enabling this option will enable outputting a file called bug_graph.png into the analysis folder.

The bug_graph.png file has two graphs which compare all the queued tests. It has a figure for bugs over time and a figure for bugs over generations.

### Edge Graphs Analysis, `[--edge-count]`

Enabling this option will enable outputting files called edge_{target}.png into the analysis folder for every target enabled in all of the queued tests.

Each edge_{target}.png has two graphs in it which compare all the queued tests.

It has a figure for edges covered over time for that target and a figure for edges covered over generation for that target.

### Overlap Analysis, `[--bug-overlap]`

Enabling this option will enable outputting a file called overlap_machine.csv into the analysis folder.

The overlap_machine.csv file tracks the number of bugs commonly found by every possible combination of queued tests.

Each combo is represented by a row. It is organized in descending order from most inclusive combo to least inclusive combo.

The file has two columns.

The first column has a list of the runs which are included in the combo. The list is delimited by `\` characters.

The second column has an integer which is the number of bugs common to every run in the combo of that row.

This option will also print overlaps to stdout. The stdout is also organized in descending order from most inclusive combo to least inclusive combo.

Each section represents a combo and is headed by the list of runs included in the combo.

Every section will list the total number of bugs common between the runs in the combo.

In each section, the stdout will then list an example input for each of those bugs. Each line in the section will have 1 bug.
