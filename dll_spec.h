#ifndef DLL_BS_H
#define DLL_BS_H

#if defined(_WIN32)
#if defined(DLL_IMPLEMENTATION)
 #define DLL_SPEC __declspec(dllexport)
#else
 #define DLL_SPEC __declspec(dllimport)
#endif
#endif

#ifndef DLL_SPEC
#define DLL_SPEC // dolce far niente...
#endif

#endif // DLL_BS_H
