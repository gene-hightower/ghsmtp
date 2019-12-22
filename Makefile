USES := ldns libglog libidn2 opendkim openssl

CXXFLAGS += -IPEGTL/include

LDLIBS += \
	-lboost_filesystem \
	-lboost_iostreams \
	-lboost_system \
	-lcdb \
	-lfmt \
	-lgflags \
	-lmagic \
	-lopendmarc \
	-lregdom \
	-lspf2 \
	-lunistring

PROGRAMS := dns_tool smtp msg sasl snd socks5

DNS := DNS DNS-rrs DNS-fcrdns DNS-packet

dns_tool_STEMS := dns_tool \
	$(DNS) \
	Domain \
	IP \
	IP4 \
	IP6 \
	POSIX \
	SPF \
	Sock \
	SockBuffer \
	TLS-OpenSSL \
	esc \
	osutil

msg_STEMS := msg \
	CDB \
	OpenDKIM \
	DMARC \
	$(DNS) \
	Domain \
	IP \
	IP4 \
	IP6 \
	POSIX \
	SPF \
	Sock \
	SockBuffer \
	TLS-OpenSSL \
	esc \
	osutil

sasl_STEMS := sasl \
	Base64 \
	Domain \
	IP4 \
	IP6 \
	POSIX \
	Sock \
	SockBuffer \
	TLS-OpenSSL \
	esc \
	osutil

smtp_STEMS := smtp \
	CDB \
	$(DNS) \
	Domain \
	IP \
	IP4 \
	IP6 \
	Message \
	POSIX \
	Pill \
	SPF \
	Session \
	Sock \
	SockBuffer \
	TLS-OpenSSL \
	esc \
	osutil

snd_STEMS := snd \
	Base64 \
	OpenDKIM \
	$(DNS) \
	Domain \
	IP \
	IP4 \
	IP6 \
	Message \
	Magic \
	POSIX \
	Pill \
	SPF \
	Sock \
	SockBuffer \
	TLS-OpenSSL \
	esc \
	osutil

socks5_STEMS := socks5 \
	$(DNS) \
	Domain \
	IP \
	IP4 \
	IP6 \
	POSIX \
	Pill \
	Sock \
	SockBuffer \
	TLS-OpenSSL \
	esc \
	osutil

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
	TLS-OpenSSL-test \
	default_init_allocator-test \
	esc-test \
	iobuffer-test \
	osutil-test

Base64-test_STEMS := Base64
CDB-test_STEMS := CDB osutil

DNS-test_STEMS := $(DNS) DNS-ldns Domain IP IP4 IP6 POSIX Sock SockBuffer TLS-OpenSSL esc osutil

Domain-test_STEMS := $(DNS) Domain IP4 IP6 POSIX Sock SockBuffer TLS-OpenSSL esc osutil
IP4-test_STEMS := $(DNS) Domain IP4 IP6 POSIX Sock SockBuffer TLS-OpenSSL esc osutil
IP6-test_STEMS := $(DNS) Domain IP4 IP6 POSIX Sock SockBuffer TLS-OpenSSL esc osutil
Magic-test_STEMS := Magic
Mailbox-test_STEMS := $(DNS) Domain IP4 IP6 POSIX Sock SockBuffer TLS-OpenSSL esc osutil
Message-test_STEMS := $(DNS) Domain IP IP4 IP6 Message Pill POSIX Sock SockBuffer TLS-OpenSSL esc osutil
POSIX-test_STEMS := POSIX
Pill-test_STEMS := Pill
SPF-test_STEMS := $(DNS) Domain IP4 IP6 SPF POSIX Sock SockBuffer TLS-OpenSSL esc osutil
osutil-test_STEMS := osutil

Session-test_STEMS := \
	CDB \
	$(DNS) \
	Domain \
	IP \
	IP4 \
	IP6 \
	Message \
	POSIX \
	Pill \
	SPF \
	Session \
	Sock \
	SockBuffer \
	TLS-OpenSSL \
	esc \
	osutil

Sock-test_STEMS := Domain IP4 IP6 POSIX Sock SockBuffer TLS-OpenSSL esc osutil
SockBuffer-test_STEMS := Domain IP4 IP6 POSIX Sock SockBuffer TLS-OpenSSL esc osutil
TLS-OpenSSL-test_STEMS := Domain IP4 IP6 POSIX TLS-OpenSSL osutil
esc-test_STEMS := esc

databases := \
	accept_domains.cdb \
	bad_recipients.cdb \
	black.cdb \
	ip-black.cdb \
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

clean-test::
	rm -f smtp.profraw
	rm -f smtp.profdata
	rm -rf $(TEST_MAILDIR)/*

%.cdb : %
	./cdb-gen < $< | cdb -c $@

clean::
	rm -f accept_domains.cdb
	rm -f black.cdb
	rm -f ip-black.cdb
	rm -f three-level-tlds.cdb
	rm -f two-level-tlds.cdb
	rm -f white.cdb cdb-gen

real-clean::
	rm -f two-level-tlds three-level-tlds public_suffix_list.dat

accept_domains.cdb: accept_domains cdb-gen
black.cdb: black cdb-gen
ip-black.cdb: ip-black cdb-gen
three-level-tlds.cdb: three-level-tlds cdb-gen
two-level-tlds.cdb: two-level-tlds cdb-gen
white.cdb: white cdb-gen

two-level-tlds three-level-tlds:
	wget --timestamping $(patsubst %,http://george.surbl.org/%,$@)

public_suffix_list.dat:
	wget --timestamping https://publicsuffix.org/list/public_suffix_list.dat

# safty_flags := # nada

# visibility_flags := # nada

lto_flags := # nada

include MKUltra/rules

regression:: $(programs) $(TEST_MAILDIR)
	@for f in testcase_dir/* ; do \
	  echo -n test `basename $$f` ""; \
	  tmp_out=`mktemp`; \
	  MAILDIR=$(TEST_MAILDIR) valgrind ./smtp < $$f > $$tmp_out; \
	  diff testout_dir/`basename $$f` $$tmp_out && echo ...pass; \
	  rm $$tmp_out; \
	done

check::
	@for f in testcase_dir/* ; do \
	  echo -n test `basename $$f` ""; \
	  tmp_out=`mktemp`; \
	  GHSMTP_SERVER_ID=digilicious.com MAILDIR=$(TEST_MAILDIR) LLVM_PROFILE_FILE=smtp.profraw ASAN_OPTIONS=detect_odr_violation=0 ./smtp < $$f > $$tmp_out; \
	  diff testout_dir/`basename $$f` $$tmp_out && echo ...pass; \
	  if [ -e smtp.profraw ] ; then mv smtp.profraw /tmp/smtp-profile/`basename $$f`; fi; \
	  rm $$tmp_out; \
	done

net-check::
	@for f in testcase_dir/* ; do \
	  echo -n test `basename $$f` ""; \
	  tmp_out=`mktemp`; \
	  ncat localhost 225 < $$f > $$tmp_out; \
	  diff testout_dir/`basename $$f` $$tmp_out && echo ...pass; \
	  if [ -e smtp.profraw ] ; then mv smtp.profraw /tmp/smtp-profile/`basename $$f`; fi; \
	  rm $$tmp_out; \
	done

check:: msg snd
	./msg --selftest
	GHSMTP_CLIENT_ID=digilicious.com ./snd --selftest

show::
	llvm-profdata merge -sparse /tmp/smtp-profile/* -o smtp.profdata
	llvm-cov show ./smtp -instr-profile=smtp.profdata
