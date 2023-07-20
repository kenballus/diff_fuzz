#!/bin/bash

fail() {
    echo -en '\033[31mError: '
    echo "$@"
    echo "Installation has failed."
    echo -en '\033[0m'
    exit 1
}

echo -n "Checking for dependencies..."
which afl-showmap &>/dev/null || fail "Please install AFL++."
which python3 &>/dev/null || fail "Please install python3."
which git &>/dev/null || fail "Please install git."
echo "done"

echo -n "Setting up venv..."
python3 -c 'import sys; exit(sys.prefix != sys.base_prefix)' || fail "Looks like you're already in a venv. This script needs to make its own venv. Please deactivate your venv and source this script again."
rm -rf url_fuzz_env || fail "Couldn't remove old venv."
python3 -m venv url_fuzz_env || fail "Couldn't make a venv."
source ./url_fuzz_env/bin/activate || fail "Couldn't activate the venv."
pip3 install --upgrade pip &>/dev/null || fail "Couldn't update pip."
echo "done"

echo -n "Installing dependencies..."
for pkg in tqdm types-tqdm python-afl black mypy pylint matplotlib; do
    pip3 install "$pkg" &>/dev/null || fail "Couldn't install remote package $pkg."
done
echo "done"

echo "Installing fuzzing targets..."
for target in targets/*; do
    echo -n "    Installing $(basename "$target")..."
    pushd "$target" || fail "Couldn't pushd into $target."
    make &>/dev/null || fail "Couldn't install local package $target."
    popd || fail "Couldn't popd from $target."
    echo "done"
done
echo "done"

mkdir -p seeds results reports benchmarking/{bench_configs,queues,analyses}

deactivate
echo -e "\033[32mYou are now in the fuzzing venv. run \`source url_fuzz_env/activate\` to exit the venv.\033[0m"
