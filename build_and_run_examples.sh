#!/bin/sh
MY_LOCATION=$(dirname $0)
pushd $MY_LOCATION/targets/baby-c && make && cd ../baby-cpp && make && cd ../.. && make
popd
