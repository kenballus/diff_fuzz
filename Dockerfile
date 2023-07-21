FROM ubuntu:kinetic

# Install required packages
RUN apt -y update && apt -y upgrade && apt -y install git make meson gcc clang wget pkg-config libglib2.0-dev neovim g++ python3 python3-pip python3-tqdm python3.10-venv

# Download diff_fuzz
RUN git clone 'https://github.com/kenballus/diff_fuzz'

# Download and install python-afl
RUN git clone 'https://github.com/jwilk/python-afl' && cd python-afl && pip3 install .

# Download and build AFL++ with QEMU support
RUN git clone 'https://github.com/AFLplusplus/AFLplusplus' && cd AFLplusplus && git checkout 4.05c && make -j$(nproc) && cd qemu_mode && ./build_qemu_support.sh && cd .. && make install -j$(nproc)

# Setup a virtual enviroment and install python dependencies
RUN cd diff_fuzz && ./setup.sh
