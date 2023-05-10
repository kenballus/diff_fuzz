.PHONY: all clean
all:
	mkdir -p seeds
	mkdir -p results
	python3 diff_fuzz.py

clean:
	rm -rf __pycache__ .mypy_cache
