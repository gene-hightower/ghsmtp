#!/bin/bash

log_dir=/tmp/Maillogs

mkdir -p ${log_dir}

cwd=`pwd`

coproc \
    ASAN_OPTIONS=detect_odr_violation=0 \
    LLVM_PROFILE_FILE=${cwd}/smtp.profraw \
    MAILDIR=/tmp/Maildir \
    GOOGLE_LOG_DIR=${log_dir} \
    GLOG_minloglevel=0 \
    ./smtp

ASAN_OPTIONS=detect_odr_violation=0 \
            ./snd \
            -service=smtp \
            -pipe=true \
            <&${COPROC[0]} >&${COPROC[1]}
