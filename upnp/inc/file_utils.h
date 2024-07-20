#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include "UpnpGlobal.h" /* for UPNP_EXPORT_SPEC */


/**
 * Helper macro for opening a file. Remember to fclose(file).
 * @param fp FILE * pointer
 * @param pem_fpath pem file path
 */
#ifdef _WIN32
#define macro_file_open(fp, filepath, ret) \
{ \
    if (filepath == NULL) { \
        printf("%s:%s(%d): Empty filepath provided.\n", __FILE__, __func__, __LINE__); \
        return ret; \
    } \
    (void) fopen_s(&fp, filepath, "r"); \
    if (fp == NULL) { \
        printf("%s:%s(%d): Error opening file: %s\n", __FILE__, __func__, __LINE__, filepath); \
        return ret; \
    } \
}
#else
#define macro_file_open(fp, filepath, mode, retFail) \
{ \
    if (filepath == NULL) { \
        printf("%s:%s(%d): Empty filepath provided.\n", __FILE__, __func__, __LINE__); \
	return retFail; \
    } \
    fp = fopen(filepath, mode); \
    if (fp == NULL) { \
        printf("%s:%s(%d): Error opening file: %s\n", __FILE__, __func__, __LINE__, filepath); \
        return retFail; \
    } \
}
#endif

UPNP_EXPORT_SPEC char * read_file(const char* filepath, const char * mode);


#endif //FILE_UTILS_H
