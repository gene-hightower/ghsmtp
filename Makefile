USES := ldns libglog libidn2 opendkim openssl

CXXFLAGS += -IPEGTL/include -Ijson/include -Icppcodec

LDLIBS += \
	-lboost_filesystem \
	-lboost_iostreams \
	-lboost_system \
	-lcdb \
	-lfmt \
	-lgflags \
	-lmagic \
	-lopenarc \
	-lopendmarc \
	-lpsl \
	-lspf2 \
	-lsrs2 \
	-lunistring

PROGRAMS := arcsign arcverify dns_tool smtp msg sasl snd socks5

arcsign_STEMS := arcsign \
	message Domain IP IP4 IP6 Mailbox OpenARC OpenDKIM OpenDMARC Pill Reply osutil esc

arcverify_STEMS := arcverify \
	message Domain IP IP4 IP6 Mailbox OpenARC OpenDKIM OpenDMARC Pill Reply osutil esc

DNS := DNS DNS-rrs DNS-fcrdns DNS-message

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
	$(DNS) \
	Domain \
	IP \
	IP4 \
	IP6 \
	Mailbox \
	OpenDKIM \
	OpenDMARC \
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
	IP \
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
	Mailbox \
	MessageStore \
	OpenARC \
	OpenDKIM \
	OpenDMARC \
	POSIX \
	Pill \
	Reply \
	SPF \
	Send \
	Session \
	Sock \
	SockBuffer \
	TLS-OpenSSL \
	esc \
	message \
	osutil

snd_STEMS := snd \
	Base64 \
	$(DNS) \
	Domain \
	IP \
	IP4 \
	IP6 \
	Magic \
	Mailbox \
	MessageStore \
	OpenDKIM \
	OpenDMARC \
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
	Hash-test \
	IP4-test \
	IP6-test \
	Magic-test \
	Mailbox-test \
	MessageStore-test \
	Now-test \
	OpenDKIM-test \
	POSIX-test \
	Pill-test \
	Reply-test \
	SPF-test \
	Send-test \
	Session-test \
	Sock-test \
	SockBuffer-test \
	TLD-test \
	TLS-OpenSSL-test \
	default_init_allocator-test \
	esc-test \
	iobuffer-test \
	is_ascii-test \
	message-test \
	osutil-test

Base64-test_STEMS := Base64
CDB-test_STEMS := CDB osutil

DNS-test_STEMS := $(DNS) DNS-ldns Domain IP IP4 IP6 POSIX Sock SockBuffer TLS-OpenSSL esc osutil

Domain-test_STEMS := $(DNS) Domain IP IP4 IP6 POSIX Sock SockBuffer TLS-OpenSSL esc osutil
IP4-test_STEMS := $(DNS) Domain IP IP4 IP6 POSIX Sock SockBuffer TLS-OpenSSL esc osutil
IP6-test_STEMS := $(DNS) Domain IP IP4 IP6 POSIX Sock SockBuffer TLS-OpenSSL esc osutil
Magic-test_STEMS := Magic
Mailbox-test_STEMS := Mailbox Domain IP IP4 IP6 osutil
MessageStore-test_STEMS := $(DNS) Domain IP IP4 IP6 MessageStore Pill POSIX Sock SockBuffer TLS-OpenSSL esc osutil
OpenDKIM-test_STEMS := OpenDKIM
POSIX-test_STEMS := POSIX
Pill-test_STEMS := Pill
Reply-test_STEMS := Reply osutil Domain IP IP4 IP6 Mailbox
SPF-test_STEMS := $(DNS) Domain IP IP4 IP6 SPF POSIX Sock SockBuffer TLS-OpenSSL esc osutil
SRS-test_STEMS := SRS Domain Mailbox IP IP4 IP6
Send-test_STEMS := $(DNS) Domain IP IP4 IP6 Mailbox OpenARC OpenDKIM OpenDMARC POSIX Pill SPF Send Sock SockBuffer TLS-OpenSSL esc message osutil

osutil-test_STEMS := osutil
message-test_STEMS := message Domain IP IP4 IP6 Mailbox OpenARC OpenDKIM OpenDMARC Pill Reply osutil esc

Session-test_STEMS := \
	CDB \
	$(DNS) \
	Domain \
	IP \
	IP4 \
	IP6 \
	Mailbox \
	MessageStore \
	OpenARC \
	OpenDKIM \
	OpenDMARC \
	POSIX \
	Pill \
	Reply \
	SPF \
	Send \
	Session \
	Sock \
	SockBuffer \
	TLS-OpenSSL \
	esc \
	message \
	osutil

Sock-test_STEMS := Domain IP IP4 IP6 POSIX Sock SockBuffer TLS-OpenSSL esc osutil
SockBuffer-test_STEMS := Domain IP IP4 IP6 POSIX Sock SockBuffer TLS-OpenSSL esc osutil
TLS-OpenSSL-test_STEMS := Domain IP IP4 IP6 POSIX TLS-OpenSSL osutil
esc-test_STEMS := esc

databases := \
	accept_domains.cdb \
	allow.cdb \
	bad_recipients.cdb \
	bad_senders.cdb \
	block.cdb \
	forward.cdb \
	ip-block.cdb \
	temp_fail.cdb

all:: $(databases) public_suffix_list.dat

TMPDIR ?= /tmp

export TEST_MAILDIR=$(TMPDIR)/Maildir
export MAILDIR=$(TEST_MAILDIR)

export ASAN_OPTIONS=detect_leaks=0

export GHSMTP_SERVER_ID=digilicious.com

export LLVM_PROFILE_FILE=smtp.profraw

$(TEST_MAILDIR):
	mkdir -p $@

#smtp.cpp: smtp.rl
#	ragel -o smtp.cpp smtp.rl

clean-test::
	rm -f smtp.profraw
	rm -f smtp.profdata
	rm -rf $(TEST_MAILDIR)/*

%.cdb : % cdb-gen
	./cdb-gen < $< | cdb -c $@

clean::
	rm -f accept_domains.cdb
	rm -f block.cdb
	rm -f cdb-gen
	rm -f forward.cdb
	rm -f ip-block.cdb
	rm -f allow.cdb

accept_domains.cdb: accept_domains cdb-gen
allow.cdb: allow cdb-gen
block.cdb: block cdb-gen
ip-block.cdb: ip-block cdb-gen
three-level-tlds.cdb: three-level-tlds cdb-gen

forward.cdb: forward
	cat $< | cdb -c $@

public_suffix_list.dat:
	wget --timestamping https://publicsuffix.org/list/public_suffix_list.dat

opt_flags := -Og

# safty_flags := # nada

# visibility_flags := # nada

lto_flags := # nada

include MKUltra/rules

regression:: $(programs) $(TEST_MAILDIR)
	@for f in testcase_dir/* ; do \
	  echo -n test `basename $$f` ""; \
	  tmp_out=`mktemp`; \
	  valgrind ./smtp < $$f > $$tmp_out; \
	  diff testout_dir/`basename $$f` $$tmp_out && echo ...pass; \
	  rm $$tmp_out; \
	done

check::
	@for f in testcase_dir/* ; do \
	  echo -n test `basename $$f` ""; \
	  tmp_out=`mktemp`; \
	   ./smtp < $$f > $$tmp_out; \
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

init::
	touch accept_domains bad_recipients bad_senders block ip-block temp_fail
	sudo dnf install  boost-devel file-devel fmt-devel glog-devel ldns-devel  libidn2-devel libopenarc-devel libopendkim-devel libopendmarc-devel libpsl-devel libspf2-devel tinycdb-devel libunistring-devel
