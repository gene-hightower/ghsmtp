/*  Ugly old C preprocessor kludge.
 */

#ifndef STRINGIFY_DOT_H
#define STRINGIFY_DOT_H

#define XSTRINGIFY(x) #x
#define STRINGIFY(x) XSTRINGIFY(x)

#endif /* STRINGIFY_DOT_H */
