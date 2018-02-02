#!/bin/bash

PROF=smtp.profraw

rm -f ${PROF} smtp.profdata

PROFD=/tmp/smtp-profile

rm -rf ${PROFD}
mkdir -p ${PROFD}

ASAN_OPTIONS=detect_odr_violation=0 ./snd
mv ${PROF} ${PROFD}/${PROF}.0

ASAN_OPTIONS=detect_odr_violation=0 ./snd -badpipline
mv ${PROF} ${PROFD}/${PROF}.1

ASAN_OPTIONS=detect_odr_violation=0 ./snd -huge_size
mv ${PROF} ${PROFD}/${PROF}.2

ASAN_OPTIONS=detect_odr_violation=0 ./snd -ip4
mv ${PROF} ${PROFD}/${PROF}.3

ASAN_OPTIONS=detect_odr_violation=0 ./snd -use_esmtp=false
mv ${PROF} ${PROFD}/${PROF}.4

llvm-profdata merge -sparse \
${PROFD}/${PROF}.0 \
${PROFD}/${PROF}.1 \
${PROFD}/${PROF}.2 \
${PROFD}/${PROF}.3 \
${PROFD}/${PROF}.4 \
-o smtp.profdata
