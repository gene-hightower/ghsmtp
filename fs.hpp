#ifndef FS_DOT_HPP
#define FS_DOT_HPP

#if __has_include(<filesystem>)

#include <filesystem>
namespace fs = std::filesystem;
using std::error_code;

#elif __has_include(<experimental / filesystem>)

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
