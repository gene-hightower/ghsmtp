#!/bin/bash

mkdir -p /tmp/Maillogs

CWD=`pwd`

coproc \
    ASAN_OPTIONS=detect_odr_violation=0 \
    LLVM_PROFILE_FILE=${CWD}/smtp.profraw \
    MAILDIR=/tmp/Maildir \
    GOOGLE_LOG_DIR=/tmp/Maillogs \
    GLOG_minloglevel=0 \
    ./smtp

ASAN_OPTIONS=detect_odr_violation=0 \
            ./snd \
            -service=smtp \
            -pipe=true \
            <&${COPROC[0]} >&${COPROC[1]}
