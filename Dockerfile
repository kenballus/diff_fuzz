FROM debian:bullseye

# Install required packages
RUN apt -y update && apt -y upgrade && apt -y install git make meson gcc wget pkg-config libglib2.0-dev neovim g++ python3 python3-pip

# Make an unprivileged user
RUN useradd --create-home fuzzing_user
USER fuzzing_user
WORKDIR /home/fuzzing_user

# Download and build AFL
RUN git clone 'https://github.com/google/AFL' && cd AFL && make -j`nproc` && cd qemu_mode && ./build_qemu_support.sh

# Install AFL (must be done as root)
USER root
RUN cd /home/fuzzing_user/AFL && make install -j`nproc`
USER fuzzing_user

# Download and install python-afl
RUN git clone 'https://github.com/jwilk/python-afl' && cd python-afl && pip3 install . && echo 'PATH=$PATH:/home/fuzzing_user/.local/bin' >> /home/fuzzing_user/.bashrc

# Download diff_fuzz
RUN git clone 'https://github.com/kenballus/diff_fuzz'
