#!/bin/bash

coproc MAILDIR=/tmp/Maildir GOOGLE_LOG_DIR=/tmp/Maillogs ./smtp
./snd -pipe=true <&${COPROC[0]} >&${COPROC[1]}
