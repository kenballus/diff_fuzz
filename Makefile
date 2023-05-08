.PHONY: all clean
all:
	python3 diff_fuzz.py

clean:
	rm -rf __pycache__ .mypy_cache
