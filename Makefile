#   This file is part of ghsmtp - Gene's simple SMTP server.
#   Copyright (C) 2013  Gene Hightower <gene@digilicious.com>

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

CPPFLAGS += \
	-I/usr/local/include

warnings = \
	-Wall \
	-Wformat=2 \
	-Wold-style-cast \
	-Woverloaded-virtual \
	-Wsign-promo

CXXFLAGS += \
	-std=c++11 \
	-MMD \
	-g -O2 \
	$(warnings)

LDLIBS += \
	-L/usr/local/lib \
	-lcrypto -lssl \
	-lglog -lgflags \
	-lboost_regex -lboost_system -lpthread \
	-lldns \
	-lspf2 \
	-lstdc++

programs = dns2 smtp smtpd
dns2_EXTRA = DNS
SPFt_EXTRA = SPF

tests = DNSt Domaint IP4t Mailboxt Messaget Nowt Pillt Sessiont SockBuffert Sockt SPFt

all: $(programs)

all_programs = $(programs) $(tests)

TEST_MAILDIR=/tmp/Maildir

$(TEST_MAILDIR):
	mkdir -p $(TEST_MAILDIR)/tmp $(TEST_MAILDIR)/new

check: $(tests) $(TEST_MAILDIR)
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

.PHONY: all check coverage regression clean
