USES := ldns libglog libcurl libidn2 opendkim openssl

CXXFLAGS += -DSMTP_HOME=$(shell pwd) -funsigned-char

LDLIBS += \
	-lboost_filesystem \
	-lboost_iostreams \
	-lboost_system \
	-lcdb \
	-lcrypto \
	-lgflags \
	-lmagic \
	-lopendmarc \
	-lregdom \
	-lspf2 \
	-lunistring

PROGRAMS := msg smtp sasl snd

msg_STEMS := msg DKIM Domain IP4 IP6 SPF esc hostname
sasl_STEMS := sasl Base64 POSIX TLS-OpenSSL
smtp_STEMS := smtp DNS Domain IP IP4 IP6 Message POSIX Pill SPF Session Sock TLS-OpenSSL date/tz esc hostname
snd_STEMS := snd Base64 DKIM DNS Domain IP4 IP6 Magic POSIX Pill Session Sock TLS-OpenSSL date/tz hostname

TESTS := \
	Base64-test \
	CDB-test \
	DNS-test \
	Domain-test \
	IP4-test \
	IP6-test \
	Magic-test \
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

Base64-test_STEMS := Base64
DNS-test_STEMS := DNS
Domain-test_STEMS := Domain IP4 IP6
IP4-test_STEMS := IP4
IP6-test_STEMS := IP6
Magic-test_STEMS := Magic
Mailbox-test_STEMS := Domain IP4 IP6
Message-test_STEMS := Domain IP4 IP6 Message Pill date/tz
Now-test_STEMS := date/tz
POSIX-test_STEMS := POSIX
Pill-test_STEMS := Pill
SPF-test_STEMS := SPF
Session-test_STEMS := DNS Domain IP IP4 IP6 POSIX Pill SPF Session Sock TLS-OpenSSL hostname
Sock-test_STEMS := POSIX Sock TLS-OpenSSL
SockBuffer-test_STEMS := POSIX Sock TLS-OpenSSL
TLS-OpenSSL-test_STEMS := POSIX TLS-OpenSSL

databases := \
	black.cdb \
	ip-black.cdb \
	ip-white.cdb \
	three-level-tlds.cdb \
	two-level-tlds.cdb \
	white.cdb \

all:: $(databases) public_suffix_list.dat

TMPDIR ?= /tmp
TEST_MAILDIR=$(TMPDIR)/Maildir

$(TEST_MAILDIR):
	mkdir -p $@

#smtp.cpp: smtp.rl
#	ragel -o smtp.cpp smtp.rl

clean::
	rm -rf stack.hh $(TEST_MAILDIR)

%.cdb : %
	./cdb-gen < $< | cdb -c $@

clean::
	rm -f two-level-tlds.cdb
	rm -f three-level-tlds.cdb
	rm -f white.cdb cdb-gen

black.cdb: black cdb-gen
ip-black.cdb: ip-black cdb-gen
ip-white.cdb: ip-white cdb-gen
three-level-tlds.cdb: three-level-tlds cdb-gen
two-level-tlds.cdb: two-level-tlds cdb-gen
white.cdb: white cdb-gen

two-level-tlds three-level-tlds:
	wget --timestamping $(patsubst %,http://george.surbl.org/%,$@)

public_suffix_list.dat:
	wget --timestamping https://publicsuffix.org/list/public_suffix_list.dat

include ../MKUltra/rules

regression: $(programs) $(TEST_MAILDIR)
	MAILDIR=$(TEST_MAILDIR) valgrind ./smtp < input.txt
	ls -l smtp
	size smtp
