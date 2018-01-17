#include "Session.hpp"

using std::experimental::string_view;
using std::string;

constexpr size_t BUFSIZE = 10 * 4 * 1024;

%%{
machine smtp;

action mb_loc_beg {
  mb_loc_beg = fpc;
}

action mb_loc_end {
  CHECK_NOTNULL(mb_loc_beg);

  mb_loc_end = fpc;
  mb_loc = string(mb_loc_beg, mb_loc_end - mb_loc_beg);

  mb_loc_beg = nullptr;
  mb_loc_end = nullptr;
}

action mb_dom_beg {
  mb_dom_beg = fpc;
}

action mb_dom_end {
  CHECK_NOTNULL(mb_dom_beg);

  mb_dom_end = fpc;
  mb_dom = string(mb_dom_beg, mb_dom_end - mb_dom_beg);

  mb_dom_beg = nullptr;
  mb_dom_end = nullptr;
}

action magic_postmaster {
  mb_loc = string("Postmaster");
  mb_dom.clear();
}

action key_end {
  param.first += static_cast<char>(::toupper(fc));
}

action val_end {
  param.second += fc;
}

action param {
  parameters.insert(param);
  param.first.clear();
  param.second.clear();
}

# action last {
#   last = true;
# }

# action chunk_size_beg {
#   chunk_sz_beg = fpc;
# }

# action chunk_size_end {
#   chunk_sz_end = fpc;
#   chunk_sz = stoll(string(chunk_sz_beg, chunk_sz_end - chunk_sz_beg));
#   chunk_sz_beg = nullptr;
#   chunk_sz_end = nullptr;
# }

#############################################################################

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

# UTF8_char = UTF8_1 | UTF8_2 | UTF8_3 | UTF8_4;

UTF8_non_ascii = UTF8_2 | UTF8_3 | UTF8_4;

# various definitions from RFC 5234

CR = 0x0D;
LF = 0x0A;

CRLF = CR LF;

SP = 0x20;
HTAB = 0x09;

WSP = SP | HTAB;

Let_dig = alpha | digit;

Ldh_str = (alpha | digit | '-')* Let_dig;

U_Let_dig = alpha | digit | UTF8_non_ascii;

U_Ldh_str = (alpha | digit | '-' | UTF8_non_ascii)* U_Let_dig;

U_label = U_Let_dig U_Ldh_str?;

label = Let_dig Ldh_str?;

sub_domain = label | U_label;

Domain = sub_domain ('.' sub_domain)*;

snum = ('2' '5' '0'..'5')
     | ('2' '0'..'4' digit)
     | ('0'..'1' digit{1,2})
     | digit{1,2}
     ;

IPv4_address_literal = snum ('.' snum){3};

IPv6_hex = xdigit{1,4};

IPv6_full = IPv6_hex (':' IPv6_hex){7};

IPv6_comp = (IPv6_hex (':' IPv6_hex){0,5})? '::' (IPv6_hex (':' IPv6_hex){0,5})?;

IPv6v4_full = IPv6_hex (':' IPv6_hex){5} ':' IPv4_address_literal;

IPv6v4_comp = (IPv6_hex (':' IPv6_hex){0,3})? '::' (IPv6_hex (':' IPv6_hex){0,3} ':')? IPv4_address_literal;

IPv6_addr = IPv6_full | IPv6_comp | IPv6v4_full | IPv6v4_comp;

IPv6_address_literal = 'IPv6:' IPv6_addr;

dcontent = graph - '\[' - '\\' - '\]';   # 33..90 | 94..126

standardized_tag = Ldh_str;

General_address_literal = standardized_tag ':' dcontent{1};

# See rfc 5321 Section 4.1.3
address_literal = '[' (IPv4_address_literal |
                  IPv6_address_literal | General_address_literal) ']';

At_domain = '@' Domain;

A_d_l = At_domain (',' At_domain)*;

qtextSMTP = print - '"' - '\\' | UTF8_non_ascii;

quoted_pairSMTP = '\\' print;

QcontentSMTP = qtextSMTP | quoted_pairSMTP;

Quoted_string = '"' QcontentSMTP* '"';

atext = alpha | digit |
        '!' | '#' |
        '$' | '%' |
        '&' | "'" |
        '*' | '+' |
        '-' | '/' |
        '=' | '?' |
        '^' | '_' |
        '`' | '{' |
        '|' | '}' |
        '~' |
        UTF8_non_ascii;

# obs_FWS = WSP+ (CRLF WSP+)*;

# FWS = ((WSP* CRLF)? WSP+) | obs_FWS;

# ccontent = ctext | quoted_pair | comment;
# comment = '(' (FWS? ccontent)* FWS? ')';
# CFWS = ((FWS? comment)+ FWS?) | FWS;

# Atom = cfws atext+ cfws;

Atom = atext+;

Dot_string = Atom ('.'  Atom)*;

Local_part = Dot_string | Quoted_string;

Mailbox = Local_part >mb_loc_beg %mb_loc_end '@'
          ((Domain | address_literal) >mb_dom_beg %mb_dom_end);

Path = "<" ((A_d_l ":")? Mailbox) ">";

Reverse_path = Path | "<>";

Forward_path = Path | "<Postmaster>"i %magic_postmaster;

esmtp_keyword = ((alpha | digit) (alpha | digit | '-')*) @key_end;

esmtp_value = ((graph - '=' | UTF8_non_ascii)+) @val_end;

esmtp_param = (esmtp_keyword ('=' esmtp_value)?) %param;

Mail_parameters = esmtp_param (' ' esmtp_param)*;

Rcpt_parameters = esmtp_param (' ' esmtp_param)*;

String = Atom | Quoted_string;

chunk_size = digit+;

#############################################################################

data := |*

 /[^\.\r\n]/ /[^\r\n]/* CRLF =>
 {
   auto len = te - ts - 2; // minus crlf
   msg.out().write(ts, len);
   msg.out() << '\n';
   msg_bytes += len + 1;
 };

 '.' /[^\r\n]/+ CRLF =>
 {
   auto len = te - ts - 3; // minus crlf and leading '.'
   msg.out().write(ts + 1, len);
   msg.out() << '\n';
   msg_bytes += len + 1;
 };

 CRLF =>
 {
   msg.out() << '\n';
   msg_bytes++;
 };

 '.' CRLF =>
 {
   session.data_msg_done(msg);
   if (msg_bytes > Config::size) {
     LOG(WARNING) << "message size " << msg_bytes << " exceeds maximium of " << Config::size;
   }
   fgoto main;
 };

*|;

#............................................................................

main := |*

 "AUTH LOGIN"i CRLF =>
 {
   session.error("AUTH not supported");
 };

 "EHLO"i SP (Domain | address_literal) CRLF =>
 {
   char const* beg = ts + 5;
   char const* end = te - 2;
   session.ehlo(string(beg, end - beg));
 };

 "HELO"i SP Domain CRLF =>
 {
   char const* beg = ts + 5;
   char const* end = te - 2;
   session.helo(string(beg, end - beg));
 };

 # optional space not specified by RFC 5321
 "MAIL FROM:"i SP? Reverse_path (SP Mail_parameters)? CRLF =>
 {
   session.mail_from(Mailbox(mb_loc, mb_dom), parameters);

   mb_loc.clear();
   mb_dom.clear();
   parameters.clear();
 };

 # optional space not specified by RFC 5321
 "RCPT TO:"i SP? Forward_path (SP Rcpt_parameters)? CRLF =>
 {
   session.rcpt_to(Mailbox(mb_loc, mb_dom), parameters);

   mb_loc.clear();
   mb_dom.clear();
   parameters.clear();
 };

 "DATA"i CRLF =>
 {
   if (session.data_start()) {
     session.data_msg(msg);
     msg_bytes = 0;
     LOG(INFO) << "calling data\n";
     fgoto data;
   }
 };

# "BDAT"i SP (chunk_size >chunk_size_beg %chunk_size_end) (SP "LAST"i @last)? CRLF =>
# {
#   LOG(INFO) << "BDAT " << chunk_sz << (last ? " LAST" : "");

#   // eat data from our buffer
#   auto space = pe - ts;
#   LOG(INFO) << "space == " << space;

#   if (last) {
#   }
#   chunk_sz = 0;
# };

 "RSET"i CRLF =>
 {
//   last = false;
   session.rset();
 };

 "NOOP"i (SP String)? CRLF =>
 {
   session.noop();
 };

 "VRFY"i (SP String)? CRLF =>
 {
   session.vrfy();
 };

 "HELP"i (SP String)? CRLF =>
 {
   session.help();
 };

 "STARTTLS"i CRLF =>
 {
   session.starttls();
 };

 "QUIT"i CRLF =>
 {
   session.quit();
 };

*|;

}%%

%% write data nofinal;

//...........................................................................

void scanner(Session& session)
{
  Message msg;
  size_t msg_bytes{0};

//  char const* chunk_sz_beg{nullptr};
//  char const* chunk_sz_end{nullptr};
//  size_t chunk_sz{0};

  char const* mb_loc_beg{nullptr};
  char const* mb_loc_end{nullptr};
  char const* mb_dom_beg{nullptr};
  char const* mb_dom_end{nullptr};

//  bool last{false};

  std::string mb_loc;
  std::string mb_dom;

  std::pair<string, string> param;
  std::unordered_map<string, string> parameters;

  static char buf[BUFSIZE];

  char* ts = nullptr;
  char* te = nullptr;
  char* pe = nullptr;

  size_t have = 0;
  bool done = false;

#ifndef __clang__
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#endif

  char const* eof = nullptr;
  int cs, act;

  %% write init;

  while (!done) {
    std::streamsize space = BUFSIZE - have;

    if (space == 0) {
      // We've used up the entire buffer storing an already-parsed token
      // prefix that must be preserved.
      session.error("out of buffer space");
      LOG(FATAL) << "out of buffer space";
    }

    char* p = buf + have;
    std::streamsize len = session.read(p, space);

    if (len == -1) { // EOF processing
      pe = p;
      len = 0;
    } else {
      pe = p + len;
      eof = nullptr;
    }

    // Check if this is the end of file.
    if (len == 0) {
      if (have == 0) {
        LOG(INFO) << "no more input";
        std::exit(EXIT_SUCCESS);
      }
      eof = pe;
      LOG(INFO) << "done";
      done = true;
    }

    LOG(INFO) << "exec \'" << string_view(buf, have + len) << "'";

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"

    %% write exec;

#pragma GCC diagnostic pop

    if (cs == smtp_error) {
      session.error("parse error");
      break;
    }

    if (ts == nullptr) {
      have = 0;
    }
    else {
      // There is a prefix to preserve, shift it over.
      have = pe - ts;
      CHECK_NE(have, 0ul);
      memmove(buf, ts, have);

      // adjust ptrs
      auto delta = ts - buf;

      mb_loc_beg -= delta;
      mb_loc_end -= delta;
      mb_dom_beg -= delta;
      mb_dom_end -= delta;

      te = buf + (te - ts);
      ts = buf;
    }
  }
}

int main(int argc, char const* argv[])
{
  close(2); // hackage to stop glog from spewing

  std::ios::sync_with_stdio(false);

  auto logdir = getenv("GOOGLE_LOG_DIR");
  if (logdir) {
    boost::system::error_code ec;
    boost::filesystem::create_directories(logdir, ec); // ignore errors;
  }
  google::InitGoogleLogging(argv[0]);

  Session session;
  session.greeting();

  scanner(session);
  LOG(INFO) << "scanner returned";
}
