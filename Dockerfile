FROM debian:bookworm

# Install required packages
RUN apt -y update && apt -y upgrade && apt -y install llvm-dev git make meson gcc clang wget pkg-config libglib2.0-dev neovim g++ python3 python3-pip python3-tqdm python3-venv

WORKDIR /app

# Download diff_fuzz
RUN git clone 'https://github.com/kenballus/diff_fuzz'

# Download and build AFL++ with QEMU support
RUN git clone 'https://github.com/AFLplusplus/AFLplusplus' && cd AFLplusplus && git checkout 4.05c && make -j$(nproc) && cd qemu_mode && ./build_qemu_support.sh && cd .. && make install -j$(nproc)

WORKDIR /app/diff_fuzz

# Setup a virtual enviroment and install python dependencies
RUN ./setup.sh

# Use the virtual enviroment
ENV VIRTUAL_ENV=fuzz_env
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

CMD ["make"]