#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include "UpnpGlobal.h" /* for UPNP_EXPORT_SPEC */

#ifdef _WIN32
#define macro_fopen(fp, filepath, mode) fopen_s(&fp, filepath, mode)
#else
#define macro_fopen(fp, filepath, mode) fp = fopen(filepath, mode)
#endif

/**
 * Helper macro for opening a file. Remember to fclose(file).
 * @param fp FILE * pointer
 * @param filepath file path to open
 * @param mode file mode to open
 * @param label label to jump to in case of failure
 */
#define macro_file_open(fp, filepath, mode, label) \
{ \
    if (filepath == NULL) { \
        printf("[File Error] %s:%s(%d): Empty filepath provided.\n", __FILE__, __func__, __LINE__); \
	    goto label; \
    } \
    macro_fopen(fp, filepath, mode); \
    if (fp == NULL) { \
        printf("[File Error] %s:%s(%d): Error opening file: %s\n", __FILE__, __func__, __LINE__, filepath); \
        goto label; \
    } \
}

/**
 * Helper macro for closing a file.
 * @param fp FILE * pointer
 */
#define macro_file_close(fp) \
{ \
    if (fp != NULL) { \
        fclose(fp); \
        fp = NULL; \
    } \
}

UPNP_EXPORT_SPEC char* read_file(const char* filepath, const char* mode);


#endif //FILE_UTILS_H
