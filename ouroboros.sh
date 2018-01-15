#!/bin/bash

coproc MAILDIR=/tmp/Maildir GOOGLE_LOG_DIR=/tmp/Maillogs ./smtp -log_data=true
./snd -pipe=true <&${COPROC[0]} >&${COPROC[1]}
