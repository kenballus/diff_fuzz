.PHONY: all format typecheck lint
all: config format typecheck lint
	python3 diff_fuzz.py

config:
	[ -e config.py ] || cp config.defpy config.py

format:
	black -l 110 *.py

typecheck:
	mypy diff_fuzz.py

lint:
	pylint --disable=line-too-long,missing-module-docstring,invalid-name,missing-function-docstring,missing-class-docstring,unnecessary-lambda-assignment,consider-using-with,too-many-locals,multiple-statements,protected-access,too-many-branches *.py
