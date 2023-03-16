FROM ubuntu:kinetic

# Make an unprivileged user and set up its PATH
RUN useradd --create-home fuzzing_user
WORKDIR /home/fuzzing_user
USER fuzzing_user
RUN mkdir -p /home/fuzzing_user/.local/bin && echo 'PATH=$PATH:/home/fuzzing_user/.local/bin' >> /home/fuzzing_user/.bashrc 

# Install required packages (must be done as root)
USER root
RUN apt -y update && apt -y upgrade && apt -y install git make meson gcc wget pkg-config libglib2.0-dev neovim g++ python3 python3-pip
USER fuzzing_user

# Download diff_fuzz
RUN git clone 'https://github.com/kenballus/diff_fuzz'

# Download and install python-afl
RUN git clone 'https://github.com/jwilk/python-afl' && cd python-afl && pip3 install .

# Download and build AFL++ with QEMU support
RUN git clone 'https://github.com/AFLplusplus/AFLplusplus' && cd AFLplusplus && git checkout 4.05c && make -j$(nproc) && cd qemu_mode && ./build_qemu_support.sh

# Install AFL++ (must be done as root)
USER root
RUN cd /home/fuzzing_user/AFLplusplus && make install -j$(nproc)
USER fuzzing_user
WORKDIR /home/fuzzing_user/diff_fuzz
