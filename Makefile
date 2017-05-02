#   This file is part of ghsmtp - Gene's simple SMTP server.
#   Copyright (C) 2014  Gene Hightower <gene@digilicious.com>

#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Affero General Public License as
#   published by the Free Software Foundation, version 3.

#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.

#   You should have received a copy of the GNU Affero General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

USES := ldns openssl libcurl

# Ragel generated code requires signed chars
# -fsigned-char

CXXFLAGS += -DSMTP_HOME=$(shell pwd)

LDLIBS += \
	-lboost_filesystem \
	-lboost_iostreams \
	-lboost_system \
	-lcdb \
	-lcrypto \
	-lglog \
	-lregdom \
	-lspf2

PROGRAMS := smtp p0f msg

p0f_STEMS := p0f

smtp_STEMS := smtp DNS POSIX SPF Session TLS-OpenSSL date/tz

msg_STEMS := msg

TESTS := \
	CDB-test \
	DNS-test \
	Domain-test \
	IP4-test \
	Mailbox-test \
	Message-test \
	Now-test \
	POSIX-test \
	Pill-test \
	SPF-test \
	Session-test \
	Sock-test \
	SockBuffer-test \
	TLD-test \
	TLS-OpenSSL-test

DNS-test_STEMS := DNS
Message-test_STEMS := date/tz
Now-test_STEMS := date/tz
POSIX-test_STEMS := POSIX
SPF-test_STEMS := SPF
Session-test_STEMS := DNS POSIX SPF Session TLS-OpenSSL
Sock-test_STEMS := POSIX TLS-OpenSSL
SockBuffer-test_STEMS := POSIX TLS-OpenSSL
TLS-OpenSSL-test_STEMS := POSIX TLS-OpenSSL

databases := \
	black.cdb \
	ip-black.cdb \
	ip-white.cdb \
	three-level-tlds.cdb \
	two-level-tlds.cdb \
	white.cdb \

all:: $(databases)

TMPDIR ?= /tmp
TEST_MAILDIR=$(TMPDIR)/Maildir

#smtp.cpp: smtp.rl
#	ragel -o smtp.cpp smtp.rl

clean::
	rm -rf stack.hh $(TEST_MAILDIR)

%.cdb : %
	./cdb-gen < $< | cdb -c $@

clean::
	rm -f two-level-*.cdb three-level-*.cdb white.cdb cdb-gen

black.cdb: black cdb-gen
ip-black.cdb: ip-black cdb-gen
ip-white.cdb: ip-white cdb-gen
three-level-tlds.cdb: three-level-tlds cdb-gen
two-level-tlds.cdb: two-level-tlds cdb-gen
white.cdb: white cdb-gen

two-level-tlds three-level-tlds:
	wget --timestamping $(patsubst %,http://george.surbl.org/%,$@)

include ../MKUltra/rules

regression: $(programs) $(TEST_MAILDIR)
	MAILDIR=$(TEST_MAILDIR) valgrind ./smtp < input.txt
	ls -l smtp
	size smtp
