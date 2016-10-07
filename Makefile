#   This file is part of ghsmtp - Gene's simple SMTP server.
#   Copyright (C) 2014  Gene Hightower <gene@digilicious.com>

#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Affero General Public License as
#   published by the Free Software Foundation, either version 3 of the
#   License, or (at your option) any later version.

#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.

#   You should have received a copy of the GNU Affero General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

warnings = \
	-Wall \
	-Wformat=2 \
	-Wold-style-cast \
	-Woverloaded-virtual

CXXFLAGS += \
	-DSMTP_HOME=$(shell pwd) \
	-MMD \
	-g -O2 \
	$(warnings)

LDFLAGS += \
	-L/usr/local/lib \

LDLIBS += \
	-lcdb \
	-lcrypto \
	-lglog \
	-lldns \
	-lregdom \
	-lspf2 \
	-lssl

programs = smtp
dns2_EXTRA = DNS
smtp_EXTRA = DNS POSIX SPF Session TLS-OpenSSL
smtpd_EXTRA = DNS POSIX SPF Session TLS-OpenSSL

tests = \
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

DNS-test_EXTRA = DNS
POSIX-test_EXTRA = POSIX
SPF-test_EXTRA = SPF
Session-test_EXTRA = DNS POSIX SPF Session TLS-OpenSSL
SockBuffer-test_EXTRA = POSIX TLS-OpenSSL
Sock-test_EXTRA = POSIX TLS-OpenSSL
TLS-OpenSSL-test_EXTRA = POSIX TLS-OpenSSL

databases = \
	black.cdb \
	ip-black.cdb \
	ip-white.cdb \
	three-level-tlds.cdb \
	two-level-tlds.cdb \
	white.cdb \

all: $(programs) $(databases)

all_programs = $(programs) $(tests)

TMPDIR ?= /tmp
TEST_MAILDIR=$(TMPDIR)/Maildir

$(TEST_MAILDIR):
	mkdir -p $(TEST_MAILDIR)/tmp $(TEST_MAILDIR)/new

check: $(tests) $(TEST_MAILDIR) $(databases)
	$(foreach t,$(tests),./$(t) ;)

vg: $(tests) $(TEST_MAILDIR) $(databases)
	$(foreach t,$(tests),valgrind ./$(t) ;)

coverage:
	$(MAKE) clean
	CXXFLAGS=--coverage LDFLAGS=-lgcov $(MAKE) check
	$(foreach t,$(tests),gcov $(t) ;)

clean::
	rm -f *.gcno *.gcda *.gcov

regression: $(programs) $(TEST_MAILDIR)
	MAILDIR=$(TEST_MAILDIR) valgrind ./smtp < input.txt
	ls -l smtp
	size smtp

smtp.hpp stack.hh: smtp.cpp
	@true

#smtp.cpp: smtp.yy
#	bison -o smtp.cpp smtp.yy

smtp.cpp: smtp.rl
	ragel -o smtp.cpp smtp.rl

clean::
	rm -f smtp.cpp smtp.hpp stack.hh

TAGS:
	etags *.[ch]* *.yy

clean::
	rm -f TAGS

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

define link_cmd
$(1)_STEMS = $(1) $$($(1)_EXTRA)
$(1)_OBJS = $$(patsubst %,%.o,$$($(1)_STEMS))
$(1)_DEPS = $$(patsubst %,%.d,$$($(1)_STEMS))

-include $$($(1)_DEPS)

$(1): $$($(1)_OBJS)
	$(CXX) -o $$@ $$^ $(LDFLAGS) $(LOADLIBES) $(LDLIBS)

clean::
	rm -f $(1) $$($(1)_OBJS) $$($(1)_DEPS)
endef

$(foreach prog,$(all_programs),$(eval $(call link_cmd,$(prog))))

.PHONY: all check coverage regression clean freshen

.PRECIOUS: %.pem
