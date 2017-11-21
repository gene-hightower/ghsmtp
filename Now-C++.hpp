/*

This version of Now added 103040 bytes of text (code) and 488 bytes of
data to my smtp program vs. the old school C/Unix style code in the
version I'm using.  Plus, it's dynamic memory for the string, etc.  It
seems to just call the same strftime from libc anyhow.

Also: this went away:

==32766== Conditional jump or move depends on uninitialised value(s)
==32766==    at 0x844FF22: __strftime_internal (strftime_l.c:543)
==32766==    by 0x8451FA5: strftime_l (strftime_l.c:459)
==32766==    by 0x7B81C88: std::__timepunct<char>::_M_put(char*, unsigned long,
char const*, tm const*) const (time_members.cc:47)
==32766==    by 0x7BD7621: std::time_put<char, std::ostreambuf_iterator<char,
std::char_traits<char> > >::do_put(std::ostreambuf_iterator<char,
std::char_traits<char> >, std::ios_base&, char, tm const*, char, char) const
(locale_facets_nonio.tcc:1343)
==32766==    by 0x7BD5BC6: std::time_put<char, std::ostreambuf_iterator<char,
std::char_traits<char> > >::put(std::ostreambuf_iterator<char,
std::char_traits<char> >, std::ios_base&, char, tm const*, char const*, char
const*) const (locale_facets_nonio.tcc:1302)
==32766==    by 0x415C71: RFC5321::Ctx::new_msg() (in
/z/home/gene/work/ghsmtp/smtp)
==32766==    by 0x4187A3: bool
tao::pegtl::internal::seq<tao::pegtl::sor<RFC5321::bogus_cmd_short,
RFC5321::data, RFC5321::quit, RFC5321::rset, RFC5321::noop, RFC5321::vrfy,
RFC5321::help, RFC5321::helo, RFC5321::ehlo, RFC5321::bdat, RFC5321::bdat_last,
RFC5321::starttls, RFC5321::rcpt_to, RFC5321::mail_from,
RFC5321::bogus_cmd_long, RFC5321::anything_else>,
tao::pegtl::discard>::match<(tao::pegtl::apply_mode)1,
(tao::pegtl::rewind_mode)1, RFC5321::action, tao::pegtl::normal,
tao::pegtl::istream_input<tao::pegtl::ascii::eol::crlf>,
RFC5321::Ctx&>(tao::pegtl::istream_input<tao::pegtl::ascii::eol::crlf>&,
RFC5321::Ctx&) (in /z/home/gene/work/ghsmtp/smtp)
==32766==    by 0x41092A: main (in /z/home/gene/work/ghsmtp/smtp)
==32766==

*/

// This on x86_64 using gcc version 7.1.1.

#ifndef NOW_DOT_HPP
#define NOW_DOT_HPP

#include <chrono>
#include <iostream>

#include <glog/logging.h>

#include "date/tz.h"

class Now {
public:
  Now()
    : v_{std::chrono::system_clock::now()}
    , str_{
          // RFC 5322 section 3.3 date-time.
          date::format("%a, %d %b %Y %H:%M:%S %z",
                       date::make_zoned(date::current_zone(),
                                        date::floor<std::chrono::seconds>(v_)))}
  {
    CHECK_EQ(str_.length(), 31) << str_ << " is the wrong length";
  }

  auto sec() const
  {
    return std::chrono::duration_cast<std::chrono::seconds>(
               v_.time_since_epoch())
        .count();
  }
  auto usec() const
  {
    return std::chrono::duration_cast<std::chrono::microseconds>(
               v_.time_since_epoch())
        .count();
  }

  std::string const& string() const { return str_; }

  bool operator==(Now const& that) const { return v_ == that.v_; }
  bool operator!=(Now const& that) const { return !(*this == that); }

private:
  std::chrono::time_point<std::chrono::system_clock> v_;
  std::string str_;

  friend std::ostream& operator<<(std::ostream& s, Now const& now)
  {
    return s << now.str_;
  }
};

#endif // NOW_DOT_HPP
