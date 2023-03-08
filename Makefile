.PHONY: all clean
all:
	black -l 110 diff_fuzz.py config.py
	mypy diff_fuzz.py config.py
	python3 diff_fuzz.py

clean:
	rm -rf traces inputs __pycache__ .mypy_cache
	mkdir traces
	mkdir inputs
