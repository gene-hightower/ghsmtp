#!/bin/bash

CXX=clang++ \
CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping" \
 LDFLAGS="-g -fprofile-instr-generate -fcoverage-mapping -lstdc++" \
make
