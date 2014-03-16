/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2013  Gene Hightower <gene@digilicious.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

%skeleton "lalr1.cc"
%require "3.0"
%expect 0

%defines
%define api.token.constructor
%define api.value.type variant
%define parse.error verbose
%define parser_class_name {Psr}

%code requires {
  #include <cctype>
  #include "Session.hpp"
  using std::swap;
}

%param { Session& session }

%code {
  #define YY_DECL yy::Psr::symbol_type yylex(Session& session)
  YY_DECL;
}

%token END      0       "end of file"
%token CRLF             "<CR><LF> pair"
%token UNPRINTABLE      "non printable"

%token <char> ' '
%token <char> '!'
%token <char> '"'
%token <char> '#'
%token <char> '$'
%token <char> '%'
%token <char> '&'
%token <char> '\''

%token <char> '('
%token <char> ')'

%token <char> '*'
%token <char> '+'
%token <char> ','
%token <char> '-'
%token <char> '.'
%token <char> '/'

%token <char> '0'
%token <char> '1'
%token <char> '2'
%token <char> '3'
%token <char> '4'
%token <char> '5'
%token <char> '6'
%token <char> '7'
%token <char> '8'
%token <char> '9'

%token <char> ':'
%token <char> ';'
%token <char> '<'
%token <char> '='
%token <char> '>'
%token <char> '?'
%token <char> '@'

%token <char> 'A'
%token <char> 'B'
%token <char> 'C'
%token <char> 'D'
%token <char> 'E'
%token <char> 'F'
%token <char> 'G'
%token <char> 'H'
%token <char> 'I'
%token <char> 'J'
%token <char> 'K'
%token <char> 'L'
%token <char> 'M'
%token <char> 'N'
%token <char> 'O'
%token <char> 'P'
%token <char> 'Q'
%token <char> 'R'
%token <char> 'S'
%token <char> 'T'
%token <char> 'U'
%token <char> 'V'
%token <char> 'W'
%token <char> 'X'
%token <char> 'Y'
%token <char> 'Z'

%token <char> '['
%token <char> '\\'
%token <char> ']'
%token <char> '^'
%token <char> '_'
%token <char> '`'

%token <char> 'a'
%token <char> 'b'
%token <char> 'c'
%token <char> 'd'
%token <char> 'e'
%token <char> 'f'
%token <char> 'g'
%token <char> 'h'
%token <char> 'i'
%token <char> 'j'
%token <char> 'k'
%token <char> 'l'
%token <char> 'm'
%token <char> 'n'
%token <char> 'o'
%token <char> 'p'
%token <char> 'q'
%token <char> 'r'
%token <char> 's'
%token <char> 't'
%token <char> 'u'
%token <char> 'v'
%token <char> 'w'
%token <char> 'x'
%token <char> 'y'
%token <char> 'z'

%token <char> '{'
%token <char> '|'
%token <char> '}'
%token <char> '~'

%type <Mailbox> fwd_path mailbox path rev_path

%type <std::string> atom domain dot_str dotnum
%type <std::string> esmtp_keyword esmtp_value label ld_str ldh_str
%type <std::string> let_dig_or_dash_str local_part qtext quoted_str
%type <std::string> snum string

%type <std::unordered_map<std::string, std::string>> mail_parameters
%type <std::pair<std::string, std::string>> esmtp_param

%type <char> alpha atext ch char digit esmtp_value_ch hunder let_dig
%type <char> let_dig_or_dash notspecial qt quoted_pair special_0
%type <char> specials x

%%

commands:
  command
| commands command
;

command:
  error
| ehlo ' ' domain CRLF  { session.ehlo($3); }
| ehlo ' ' '[' dotnum ']' CRLF
                        { session.ehlo($4); }
| helo ' ' domain CRLF  { session.helo($3); }
| helo ' ' '[' dotnum ']' CRLF
                        { session.helo($4); }

| mail rev_path CRLF    { session.mail_from($2, std::unordered_map<std::string, std::string>()); }
| mail rev_path ' ' mail_parameters CRLF
                        { session.mail_from($2, $4); }

| rcpt fwd_path CRLF    { session.rcpt_to($2, std::unordered_map<std::string, std::string>()); }
| rcpt fwd_path ' ' mail_parameters CRLF
                        { session.rcpt_to($2, $4); }

| data CRLF             { session.data(); }
| rset CRLF             { session.rset(); }

| noop CRLF             { session.noop(); }
| noop ' ' string CRLF  { session.noop(); }

| vrfy                  { session.vrfy(); }
| vrfy ' ' string CRLF  { session.vrfy(); }

| help CRLF             { session.help(); }
| help ' ' string CRLF  { session.help(); }

| starttls              { session.starttls(); }

| quit CRLF             { session.quit(); }
;

string:
  char                  {}
| string char           {}
;

rev_path:
  path                  { swap($$, $1); }
| spaces path           { swap($$, $2); }
| '<' '>'               { $$ = Mailbox(); }
| spaces '<' '>'        { $$ = Mailbox(); }
;

fwd_path:
  path                  { swap($$, $1); }
| spaces path           { swap($$, $2); }
;

path:
  '<' mailbox '>'       { swap($$, $2); }
| '<' a_d_l ':' mailbox '>'
                        { swap($$, $4); }
;

mail_parameters:
  esmtp_param           { $$[$1.first] = $1.second; }
| mail_parameters ' ' esmtp_param
                        { swap($$, $1); $$[$3.first] = $3.second; }
;

esmtp_param:
  esmtp_keyword         { $$.first = $1; }
| esmtp_keyword '=' esmtp_value
                        { $$.first = $1; $$.second = $3;  }
;

esmtp_keyword:
  let_dig               { $$.push_back($1); }
| let_dig let_dig_or_dash_str
                        { $$.push_back($1); $$ += $2; }
;

let_dig_or_dash:
  let_dig               { $$=$1; }
| '-'                   { $$=$1; }
;

let_dig_or_dash_str:
  let_dig_or_dash       { $$.push_back($1); }
| let_dig_or_dash_str let_dig_or_dash
                        { swap($$, $1); $$.push_back($2); }
;

esmtp_value:
  esmtp_value_ch        { $$.push_back($1); }
| esmtp_value esmtp_value_ch
                        { swap($$, $1); $$.push_back($2); }
;

esmtp_value_ch:
  '!' {$$=$1;}
| '"' {$$=$1;}
| '#' {$$=$1;}
| '$' {$$=$1;}
| '%' {$$=$1;}
| '&' {$$=$1;}
| '\''{$$=$1;}
| '(' {$$=$1;}
| ')' {$$=$1;}
| '*' {$$=$1;}
| '+' {$$=$1;}
| ',' {$$=$1;}
| '-' {$$=$1;}
| '.' {$$=$1;}
| '/' {$$=$1;}

| digit

| ':' {$$=$1;}
| ';' {$$=$1;}
| '<' {$$=$1;}

// missing '='

| '>' {$$=$1;}
| '?' {$$=$1;}
| '@' {$$=$1;}

| alpha

| '[' {$$=$1;}
| '\\' {$$=$1;}
| ']' {$$=$1;}
| '^' {$$=$1;}
| '_' {$$=$1;}
| '`' {$$=$1;}
| '{' {$$=$1;}
| '|' {$$=$1;}
| '}' {$$=$1;}
| '~' {$$=$1;}
;

a_d_l:
  '@' domain
| a_d_l ',' '@' domain
;

mailbox:
  local_part '@' domain { $$ = Mailbox($1, $3); }
| local_part '@' '[' dotnum ']'
                        { $$ = Mailbox($1, $4); }
;

local_part:
  dot_str               { swap($$, $1); }
| quoted_str            { swap($$, $1); }
;

dot_str:
  atom                  { swap($$, $1); }
| dot_str '.' atom      { swap($$, $1); $$.push_back('.'); $$ += $3; }
;

atom:
  atext                 { $$.push_back($1); }
| atom atext            { swap($$, $1); $$.push_back($2); }
;

atext:
  alpha                 {$$=$1;}
| digit                 {$$=$1;}
| notspecial            {$$=$1;}
;

quoted_str:
  '"' qtext '"'         { swap($$, $2); }
;

quoted_pair:
  '\\' x                { $$ = $2; }
;

qtext:
  quoted_pair           { $$.push_back($1); }
| qtext quoted_pair     { swap($$, $1); $$.push_back($2); }
| qt                    { $$.push_back($1); }
| qtext qt              { swap($$, $1); $$.push_back($2); }
;

char: ch | quoted_pair;

spaces:
  ' '
| spaces ' '
;

/* Not so much RFC 5321, but RFC 1123: */

domain:
  label                 { swap($$, $1); }
| label '.'             { swap($$, $1); $$.push_back('.'); }
| label '.' domain      { swap($$, $1); $$.push_back('.'); $$ += $3; }
;

label:
  let_dig               { $$.push_back($1); }
| let_dig ld_str        { $$.push_back($1); $$ += $2; }
| let_dig ldh_str ld_str
                        { $$.push_back($1); $$ += $2; $$ += $3; }
;

ld_str:
  let_dig               { $$.push_back($1); }
| ld_str let_dig        { swap($$, $1); $$.push_back($2); }
;

ldh_str:
  hunder                { $$.push_back($1); }
| ld_str hunder         { swap($$, $1); $$.push_back($2); }
| ldh_str ld_str hunder { swap($$, $1); $$ += $2; $$.push_back($3); }
;

hunder:
  '-' {$$=$1;}
| '_' {$$=$1;}
;

let_dig:
  alpha {$$=$1;}
| digit {$$=$1;}
;

dotnum: snum '.' snum '.' snum '.' snum;

snum:
  digit                 { $$=$1; }
| digit digit           { $$=$1; $$+=$2; }
| digit digit digit     { $$=$1; $$+=$2; $$+=$3; }
;

alpha:
  'A' {$$=$1;} | 'B' {$$=$1;} | 'C' {$$=$1;} | 'D' {$$=$1;} | 'E' {$$=$1;}
| 'F' {$$=$1;} | 'G' {$$=$1;} | 'H' {$$=$1;} | 'I' {$$=$1;} | 'J' {$$=$1;}
| 'K' {$$=$1;} | 'L' {$$=$1;} | 'M' {$$=$1;} | 'N' {$$=$1;} | 'O' {$$=$1;} 
| 'P' {$$=$1;} | 'Q' {$$=$1;} | 'R' {$$=$1;} | 'S' {$$=$1;} | 'T' {$$=$1;}
| 'U' {$$=$1;} | 'V' {$$=$1;} | 'W' {$$=$1;} | 'X' {$$=$1;} | 'Y' {$$=$1;} 
| 'Z' {$$=$1;}
| 'a' {$$=$1;} | 'b' {$$=$1;} | 'c' {$$=$1;} | 'd' {$$=$1;} | 'e' {$$=$1;}
| 'f' {$$=$1;} | 'g' {$$=$1;} | 'h' {$$=$1;} | 'i' {$$=$1;} | 'j' {$$=$1;}
| 'k' {$$=$1;} | 'l' {$$=$1;} | 'm' {$$=$1;} | 'n' {$$=$1;} | 'o' {$$=$1;} 
| 'p' {$$=$1;} | 'q' {$$=$1;} | 'r' {$$=$1;} | 's' {$$=$1;} | 't' {$$=$1;}
| 'u' {$$=$1;} | 'v' {$$=$1;} | 'w' {$$=$1;} | 'x' {$$=$1;} | 'y' {$$=$1;} 
| 'z' {$$=$1;}
;

digit:
  '0' {$$=$1;} | '1' {$$=$1;} | '2' {$$=$1;} | '3' {$$=$1;} | '4' {$$=$1;}
| '5' {$$=$1;} | '6' {$$=$1;} | '7' {$$=$1;} | '8' {$$=$1;} | '9' {$$=$1;}
;

special_0:   /* specials without " and \ */
  '(' {$$=$1;}
| ')' {$$=$1;}
| ',' {$$=$1;}
| '.' {$$=$1;}
| ':' {$$=$1;}
| ';' {$$=$1;}
| '<' {$$=$1;}
| '>' {$$=$1;}
| '@' {$$=$1;}
| '[' {$$=$1;}
| ']' {$$=$1;}
;

specials:
  special_0     {$$=$1;}
/* These are the characters that must be escaped: */
| '"'           {$$=$1;}
| '\\'          {$$=$1;}
;

notspecial:
  '!' {$$=$1;}
//'"' <in specials>
| '#' {$$=$1;}
| '$' {$$=$1;}
| '%' {$$=$1;}
| '&' {$$=$1;}
| '\''{$$=$1;}
//'(' <in special_0>
//')' <in special_0>
| '*' {$$=$1;}
| '+' {$$=$1;}
//',' <in special_0>
| '-' {$$=$1;}
//'.' <in special_0>
| '/' {$$=$1;}

// digits

//':' <in special_0>
//';' <in special_0>
//'<' <in special_0>
| '=' {$$=$1;}
//'>' <in special_0>
| '?' {$$=$1;}
//'@' <in special_0>

// alpha UC

//'[' <in special_0>
//'\\'<in specials>
//']' <in special_0>
| '^' {$$=$1;}
| '_' {$$=$1;}
| '`' {$$=$1;}

// alpha LC

| '{' {$$=$1;}
| '|' {$$=$1;}
| '}' {$$=$1;}
| '~' {$$=$1;}
;

ch:
  alpha {$$=$1;}
| digit {$$=$1;}
| notspecial {$$=$1;}
;

qt:
  alpha {$$=$1;}
| digit {$$=$1;}
| special_0 {$$=$1;}
| notspecial {$$=$1;}
| ' ' {$$=$1;}
;

x:
  alpha {$$=$1;}
| digit {$$=$1;}
| specials {$$=$1;}
| notspecial {$$=$1;}
| ' ' {$$=$1;}
;

/* SMTP commands */

data: d a t a;
ehlo: e h l o;
helo: h e l o;
help: h e l p;
mail: m a i l ' ' f r o m ':';
noop: n o o p;
quit: q u i t;
rcpt: r c p t ' ' t o ':';
rset: r s e t;
vrfy: v r f y;

starttls: s t a r t t l s;

/* case insensitive alphabet, used for above commands */

a: 'a' | 'A';
c: 'c' | 'C';
d: 'd' | 'D';
e: 'e' | 'E';
f: 'f' | 'F';
h: 'h' | 'H';
i: 'i' | 'I';
l: 'l' | 'L';
m: 'm' | 'M';
n: 'n' | 'N';
o: 'o' | 'O';
p: 'p' | 'P';
q: 'q' | 'Q';
r: 'r' | 'R';
s: 's' | 'S';
t: 't' | 'T';
u: 'u' | 'U';
v: 'v' | 'V';
y: 'y' | 'Y';

%%

YY_DECL
{
  static int line_length;
  static std::string line;

  int c = session.in().get();

  if (-1 == c) {
    if (session.timed_out())
      session.time();
    return yy::Psr::make_END();
  }

  if ('\r' == c) {
    c = session.in().get();
    if ('\n' == c) {
      line_length = 0;
      LOG(INFO) << line;
      line.clear();
      return yy::Psr::make_CRLF();
    }
    session.in().unget();
    c = '\r';
  }

  if (1024 == ++line_length) {
    LOG(WARNING) << "line too long";
  }

  if (!std::isprint(c)) {
    LOG(WARNING) << "unprintable character 0x"
                 << std::hex << std::setfill('0') << std::setw(2)
                 << static_cast<unsigned>(c);
    return yy::Psr::make_UNPRINTABLE();
  }

  line.push_back(c);
  return yy::Psr::symbol_type(static_cast<yy::Psr::token_type>(c), c);
}

void yy::Psr::error(std::string const& msg)
{
  session.error(msg);
}

int main(int argc, char const* argv[])
{
  std::ios::sync_with_stdio(false);
  Logging::init(argv[0]);

  Session session;
  session.greeting();

  yy::Psr psr(session); //  psr.set_debug_level(true);
  psr.parse();
}
