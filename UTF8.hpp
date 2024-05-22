#ifndef UTF8_DOT_HPP
#define UTF8_DOT_HPP

// clang-format off

struct UTF8_tail : range<'\x80', '\xBF'> {};

struct UTF8_1 : range<'\x00', '\x7F'> {};

struct UTF8_2 : seq<range<'\xC2', '\xDF'>, UTF8_tail> {};

struct UTF8_3 : sor<seq<one<'\xE0'>, range<'\xA0', '\xBF'>, UTF8_tail>,
                    seq<range<'\xE1', '\xEC'>, rep<2, UTF8_tail>>,
                    seq<one<'\xED'>, range<'\x80', '\x9F'>, UTF8_tail>,
                    seq<range<'\xEE', '\xEF'>, rep<2, UTF8_tail>>> {};

struct UTF8_4 : sor<seq<one<'\xF0'>, range<'\x90', '\xBF'>, rep<2, UTF8_tail>>,
                    seq<range<'\xF1', '\xF3'>, rep<3, UTF8_tail>>,
                    seq<one<'\xF4'>, range<'\x80', '\x8F'>, rep<2, UTF8_tail>>> {};

struct UTF8_non_ascii : sor<UTF8_2, UTF8_3, UTF8_4> {};

struct VUCHAR : sor<VCHAR, UTF8_non_ascii> {};

// clang-format on

#endif // UTF8_DOT_HPP
