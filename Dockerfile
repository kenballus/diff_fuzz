FROM debian:bullseye

RUN apt -y update && apt -y upgrade && apt -y install git make meson gcc wget pkg-config libglib2.0-dev neovim g++

RUN useradd --create-home fuzzing_user
USER fuzzing_user

# Get AFLplusplus
RUN cd && wget 'https://github.com/AFLplusplus/AFLplusplus/archive/refs/tags/4.05c.tar.gz' && tar xf 4.05c.tar.gz && rm 4.05c.tar.gz && cd AFLplusplus-4.05c && make -j`nproc` && cd qemu_mode && ./build_qemu_support.sh

USER root
RUN cd /home/fuzzing_user/AFLplusplus-4.05c && make install -j`nproc`

# Get diff_fuzz
USER fuzzing_user
RUN cd && git clone 'https://github.com/kenballus/diff_fuzz'
