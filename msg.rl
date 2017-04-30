#include <glog/logging.h>

#include <experimental/string_view>
using std::experimental::string_view;

#define BOOST_FILESYSTEM_NO_DEPRECATED
#include <boost/filesystem.hpp>

#include <boost/iostreams/device/mapped_file.hpp>

%%{
machine msg;
write data;
}%%

// https://tools.ietf.org/html/rfc5322

void proc_msg(string_view msg)
{
  int cs;

  auto p = msg.data();
  auto pe = p + msg.length();

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"

%%{

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

CR = 0x0D;
LF = 0x0A;

CRLF = CR LF;

SP = 0x20;
HTAB = 0x09;

WSP = SP | HTAB;

DQUOTE = '"';

DIGIT = '0'..'9';

ALPHA = 'A'..'Z' | 'a'..'z';

VCHAR = 0x21..0x7E | UTF8_non_ascii;

obs_NO_WS_CTL = 1..8   |        # US-ASCII control
                11     |        #  characters that do not
                12     |        #  include the carriage
                14..31 |        #  return, line feed, and
                127;            #  white space characters

obs_qp = '\\' (0x0 | obs_NO_WS_CTL | LF | CR);

quoted_pair =  ('\\' (VCHAR | WSP)) | obs_qp;

obs_FWS = WSP+ (CRLF WSP+)*;

FWS = ([WSP* CRLF] WSP+) | obs_FWS;

text = (1..127 - CR - LF) | UTF8_non_ascii;

obs_body = ((LF* CR* ((0 | text) LF* CR*)*) | CRLF)*;

body = ((text{0,998} CRLF)* text{0,998}) | obs_body;

day_name = "Mon"i | "Tue"i | "Wed"i | "Thu"i |
           "Fri"i | "Sat"i | "Sun"i;

ctext = 33..39 |        # Printable US-ASCII
        42..91 |        #  characters not including
        93..126 |       #  "(", ")", or "\"
        obs_ctext
        ;

comment = '(' (FWS? (ctext | quoted_pair | comment))* FWS? ')';

CFWS = ((FWS? comment)+ FWS?) | FWS;

obs_day_of_week = CFWS? day_name CFWS?;

day_of_week = (FWS? day_name) | obs_day_of_week;



date_time = ( day_of_week ',' )? date time CFWS?;


orig_date = "Date:"i date_time CRLF;

fields = (trace
          optional_field* |
          (resent_date |
          resent_from |
          resent_sender |
          resent_to |
          resent_cc |
          resent_bcc |
          resent_msg_id)*)*
         (orig_date |
         from |
         sender |
         reply_to |
         to |
         cc |
         bcc |
         message_id |
         in_reply_to |
         references |
         subject |
         comments |
         keywords |
         optional_field)*
         ;

msg := (fields | obs_fields)
       (CRLF body)?
       ;

write init;
write exec;

}%%

#pragma GCC diagnostic pop
}

int main(int argc, char const* argv[])
{
  for (auto i=1; i<argc; ++i) {
    boost::filesystem::path name(argv[i]);
    boost::iostreams::mapped_file_source f(name);  
    proc_msg(string_view(f.data(), f.size()));
  }
}
