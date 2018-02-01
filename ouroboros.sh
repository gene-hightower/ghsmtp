#!/bin/bash

mkdir -p /tmp/Maillogs

CWD=`pwd`

coproc \
    ASAN_OPTIONS=detect_odr_violation=0 \
    LLVM_PROFILE_FILE=${CWD}/smtp.profraw \
    MAILDIR=/tmp/Maildir \
    GOOGLE_LOG_DIR=/tmp/Maillogs \
    GLOG_minloglevel=0 \
    ./smtp \
    -log_data=true

ASAN_OPTIONS=detect_odr_violation=0 ./snd -log_data=true -pipe=true <&${COPROC[0]} >&${COPROC[1]}
