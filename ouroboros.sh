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
    ./smtp -use_prdr=true

ASAN_OPTIONS=detect_odr_violation=0 \
            ./snd \
            -use_chunking=false \
            -log_data \
            -service=smtp \
            -pipe=true \
            -smtp_to='a@digilicious.com' \
            -smtp_to2='anybody@digilicious.com' \
            -smtp_to3='c@digilicious.com' \
            <&${COPROC[0]} >&${COPROC[1]}
