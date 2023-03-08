.PHONY: all clean
all:
	mkdir -p traces
	mkdir -p inputs
	python3 diff_fuzz.py

clean:
	rm -rf traces inputs __pycache__ .mypy_cache
	mkdir traces
	mkdir inputs
