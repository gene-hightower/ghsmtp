#ifndef FS_DOT_HPP
#define FS_DOT_HPP

// Normally I would consider it rude to have a "using …" in a header
// file, but in this case the whole point is to conditionally define a
// short namespace that gives us a filesystem library.

#if __has_include(<filesystem>)

#include <filesystem>
namespace fs = std::filesystem;
using std::error_code;

// clang-format off
#elif __has_include(<experimental/filesystem>)
// clang-format on

#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
using std::error_code;

#else

#define BOOST_FILESYSTEM_NO_DEPRECATED
#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;
using boost::system::error_code;

#endif

#endif // FS_DOT_HPP
