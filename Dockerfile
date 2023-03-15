FROM debian:bullseye

RUN apt -y update && apt -y upgrade && apt -y install git make meson gcc wget pkg-config libglib2.0-dev neovim g++ python3 python3-pip

RUN useradd --create-home fuzzing_user
USER fuzzing_user

WORKDIR /home/fuzzing_user

# Download and build AFLplusplus
RUN wget 'https://github.com/AFLplusplus/AFLplusplus/archive/refs/tags/4.05c.tar.gz' && tar xf 4.05c.tar.gz && rm 4.05c.tar.gz && cd AFLplusplus-4.05c && make -j`nproc` && cd qemu_mode && ./build_qemu_support.sh

# Install AFLplusplus
USER root
RUN cd /home/fuzzing_user/AFLplusplus-4.05c && make install -j`nproc`
USER fuzzing_user

# Download and install python-afl
RUN git clone 'https://github.com/jwilk/python-afl' && cd python-afl && pip3 install .

# Download diff_fuzz
RUN git clone 'https://github.com/kenballus/diff_fuzz'
