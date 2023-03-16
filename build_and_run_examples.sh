#!/bin/sh
pushd $(dirname $0)
cd targets/baby-c && make && cd ../baby-cpp && make && cd ../.. && make
popd
