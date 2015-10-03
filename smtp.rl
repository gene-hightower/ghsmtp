#include <fstream>
#include <iostream>

#include <boost/utility/string_ref.hpp>

#include "Session.hpp"

constexpr unsigned BUFSIZE = 128;

%%{
machine smtp;

UTF8_tail = 0x80..0xBF;

UTF8_1 = 0x00..0x7F;

UTF8_2 = 0xC2..0xDF UTF8_tail;

UTF8_3 = (0xE0 0xA0..0xBF UTF8_tail)
       | (0xE1..0xEC UTF8_tail{2})
       | (0xED 0x80..0x9F UTF8_tail)
       | (0xEE..0xEF UTF8_tail{2})
       ;

UTF8_4 = (0xF0 0x90..0xBF UTF8_tail{2})
       | (0xF1..0xF3 UTF8_tail{3})
       | (0xF4 0x80..0x8F UTF8_tail{2})
       ;

UTF8_char = UTF8_1 | UTF8_2 | UTF8_3 | UTF8_4;

UTF8_non_ascii = UTF8_2 | UTF8_3 | UTF8_4;

crlf = '\r\n';

let_dig = alpha | digit;

ldh_str = (alpha | digit | '-')* let_dig;

sub_domain = let_dig ldh_str?;

domain = sub_domain ('.' sub_domain)*;

snum = ('2' '5' '0'..'5')
     | ('2' '0'..'4' digit)
     | ('0'..'1' digit{1,2})
     | digit{1,2}
     ;

ipv4_address_literal = snum ('.'  snum){3};

ipv6_hex = xdigit{1,4};

ipv6_full = ipv6_hex (':' ipv6_hex){7};

ipv6_comp = (ipv6_hex (':' ipv6_hex){0,5})? '::' (ipv6_hex (':' ipv6_hex){0,5})?;

ipv6v4_full = ipv6_hex (':' ipv6_hex){5} ':' ipv4_address_literal;

ipv6v4_comp = (ipv6_hex (':' ipv6_hex){0,3})? '::' (ipv6_hex (':' ipv6_hex){0,3} ':')? ipv4_address_literal;

ipv6_addr = ipv6_full | ipv6_comp | ipv6v4_full | ipv6v4_comp;

ipv6_address_literal = 'ipv6:' ipv6_addr;

dcontent = graph - '[';

standardized_tag = ldh_str;

general_address_literal = standardized_tag ':' dcontent{1};

# See rfc 5321 Section 4.1.3
address_literal = '[' (ipv4_address_literal | ipv6_address_literal | general_address_literal) ']';

at_domain = '@' domain;

a_d_l = at_domain (',' at_domain)*;

qtext_smtp = print - '"' - '\\';

quoted_pair_smtp = '\\' print;

qcontent_smtp = qtext_smtp | quoted_pair_smtp;

quoted_string = '"' qcontent_smtp* '"';

atext = alpha | digit
      | '!' | '#' | '$' | '%' | '&' | "'"
      | '*' | '+' | '-' | '/' | '=' | '?'
      | '^' | '_' | '`' | '{' | '|' | '}'
      | '~'
      | UTF8_non_ascii
      ;

wsp = ' ' | 9;

obs_fws = wsp+ (crlf wsp+)*;

fws = ((wsp* crlf)? wsp+) | obs_fws;

# ccontent = ctext | quoted_pair | comment;
# comment = '(' (fws? ccontent)* fws? ')';
# cfws = ((fws? comment)+ fws?) | fws;

# atom = cfws atext+ cfws;

atom = atext+;

dot_string = atom ('.'  atom)*;

local_part = dot_string | quoted_string;

mailbox = local_part '@' (domain | address_literal);

path = '<' (a_d_l ':')? mailbox '>';

reverse_path = path | '<>';

esmtp_keyword = (alpha | digit) (alpha | digit | '-')*;

esmtp_value = (graph - '=')+;

esmtp_param = esmtp_keyword ('=' esmtp_value)?;

mail_parameters = esmtp_param (' ' esmtp_param)*;

forward_path = path;

rcpt_parameters = esmtp_param (' ' esmtp_param)*;

string = atom | quoted_string;

action protocol_err {
  fhold; fgoto line;
}

data := |*

  /[^\.].+\r\n/ => { std::cout << "0\n"; };

  /\..+\r\n/ => { std::cout << "1\n"; };

  /\.\r\n/ => { std::cout << "2\n"; fret; };

*|;

main := |*

 'ehlo'i ' ' (domain | address_literal) crlf =>
 { std::cout << boost::string_ref(ts, static_cast<size_t>(te - ts)); };

 'helo'i ' ' domain crlf =>
 { std::cout << boost::string_ref(ts, static_cast<size_t>(te - ts)); };

 'mail from:'i reverse_path (' ' mail_parameters)? crlf =>
 { std::cout << boost::string_ref(ts, static_cast<size_t>(te - ts)); };

 'rcpt to:'i forward_path (' ' rcpt_parameters)? crlf =>
 { std::cout << boost::string_ref(ts, static_cast<size_t>(te - ts)); };

 'data'i crlf =>
 { std::cout << "calling data\n"; fcall data; };

 'rset'i crlf =>
 { std::cout << boost::string_ref(ts, static_cast<size_t>(te - ts)); };

 'noop'i (' ' string)? crlf =>
 { std::cout << boost::string_ref(ts, static_cast<size_t>(te - ts)); };

 'vrfy'i (' ' string)? crlf =>
 { std::cout << boost::string_ref(ts, static_cast<size_t>(te - ts)); };

 'help'i (' ' string)? crlf =>
 { std::cout << boost::string_ref(ts, static_cast<size_t>(te - ts)); };

 'starttls'i crlf =>
 { std::cout << boost::string_ref(ts, static_cast<size_t>(te - ts)); };

 'quit'i crlf =>
 { std::cout << boost::string_ref(ts, static_cast<size_t>(te - ts)); };

*|;

}%%

%% write data nofinal;

void scanner(Session& session)
{
  static char buf[BUFSIZE];

  char* ts;
  char* te = nullptr;

  int cs;
  int have = 0;

  int done = 0;
  int act;
  int stack[1];
  int top;

  %% write init;

  while (!done) {
    char* p = buf + have;
    char* eof = nullptr;
    int space = BUFSIZE - have;

    if (space == 0) {
      // We've used up the entire buffer storing an already-parsed token
      // prefix that must be preserved.
      session.error("out of buffer space");
      LOG(FATAL) << "out of buffer space";
    }

    session.in().peek(); // buffer up some input
    std::streamsize len = session.in().readsome(p, space);
    char *pe = p + len;

    // Check if this is the end of file.
    if (len < space) {
      done = 1;
    }

    %% write exec;

    if (cs == smtp_error) {
      session.error("parse error");
      break;
    }

    if (ts == 0) {
      have = 0;
    } else {
      // There is a prefix to preserve, shift it over.
      have = pe - ts;
      memmove(buf, ts, have);
      te = buf + (te - ts);
      ts = buf;
    }
  }
}

int main(int argc, char const* argv[])
{
  std::ios::sync_with_stdio(false);
  Logging::init(argv[0]);

  Session session;
  session.greeting();

  scanner(session);
}
