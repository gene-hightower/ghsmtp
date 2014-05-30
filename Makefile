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
	-Woverloaded-virtual \
	-Wsign-promo

CXXFLAGS += \
	-I/usr/local/ssl/include \
	-DSMTP_HOME=$(shell pwd) \
	-std=c++1y \
	-MMD \
	-g -O2 \
	$(warnings)

LDLIBS += \
	-L/usr/local/ssl/lib \
	-lcrypto -lssl \
	-lglog -lgflags \
	-lldns \
	-lspf2 \
	-lregdom \
	-lcdb \
	-lm \
	-lstdc++

programs = smtp smtpd dns2
dns2_EXTRA = DNS
smtp_EXTRA = DNS POSIX SPF Session TLS-OpenSSL
smtpd_EXTRA = DNS POSIX SPF Session TLS-OpenSSL

tests = \
	CDBt \
	DNSt \
	Domaint \
	IP4t \
	Mailboxt \
	Messaget \
	Nowt \
	POSIXt \
	Pillt \
	SPFt \
	Sessiont \
	SockBuffert \
	Sockt \
	TLDt \
	TLS-OpenSSLt

DNSt_EXTRA = DNS
POSIXt_EXTRA = POSIX
SPFt_EXTRA = SPF
Sessiont_EXTRA = DNS POSIX SPF Session TLS-OpenSSL
SockBuffert_EXTRA = POSIX TLS-OpenSSL
Sockt_EXTRA = POSIX TLS-OpenSSL
TLS-OpenSSLt_EXTRA = POSIX TLS-OpenSSL

databases = \
	ip-black.cdb \
	ip-white.cdb \
	three-level-tlds.cdb \
	black.cdb \
	white.cdb \
	two-level-tlds.cdb

all: $(programs) $(databases)

all_programs = $(programs) $(tests)

TEST_MAILDIR=/tmp/Maildir

$(TEST_MAILDIR):
	mkdir -p $(TEST_MAILDIR)/tmp $(TEST_MAILDIR)/new

check: $(tests) $(TEST_MAILDIR) $(databases)
	$(foreach t,$(tests),./$(t) ;)

coverage:
	$(MAKE) clean
	CXXFLAGS=--coverage $(MAKE) check
	$(foreach t,$(tests),gcov $(t) ;)

clean::
	rm -f *.gcno *.gcda *.gcov

regression: $(programs) $(TEST_MAILDIR)
	MAILDIR=$(TEST_MAILDIR) valgrind ./smtp < input.txt
	ls -l smtp
	size smtp

smtp.hpp stack.hh: smtp.cpp
	@true

smtp.cpp: smtp.yy
	bison -o smtp.cpp smtp.yy

clean::
	rm -f smtp.cpp smtp.hpp stack.hh

TAGS:
	etags *.[ch]* *.yy

clean::
	rm -f TAGS

%.cdb : % cdb-gen
	./cdb-gen < $^ | cdb -c $@

clean::
	rm -f two-level-*.cdb three-level-*.cdb white.cdb cdb-gen

ip-black.cdb: ip-black
ip-white.cdb: ip-white

two-level-tlds.cdb: two-level-tlds
three-level-tlds.cdb: three-level-tlds

black.cdb: black
white.cdb: white

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
