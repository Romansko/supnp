#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include "UpnpGlobal.h" /* for UPNP_EXPORT_SPEC */
#include <stddef.h>
#include <stdio.h>

#ifdef _WIN32
#define _fopen(fp, filepath, mode) fopen_s(&fp, filepath, mode)
#else
#define _fopen(fp, filepath, mode) fp = fopen(filepath, mode)
#endif

#define FILE_OP_ERR  0
#define FILE_OP_OK   1

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
    _fopen(fp, filepath, mode); \
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

/*!
 * \brief Retrieve file size.
 *
 * \param fp file pointer.
 *
 * \return file size.
 */
UPNP_EXPORT_SPEC size_t get_file_size(FILE* fp);

/*!
 * \brief Read file content.
 *
 * \Note Remember to free the returned pointer.
 *
 * \return file content on success, NULL on failure.
 */
UPNP_EXPORT_SPEC char* read_file(const char* filepath, const char* mode, size_t* file_size);

/*!
 * \brief Write data to file.
 *
 * \param filepath file path to write.
 * \param data data to write.
 * \param size size of data.
 *
 * \return FILE_OP_OK on success, FILE_OP_ERR on failure.
 */
UPNP_EXPORT_SPEC int write_file(const char* filepath, const unsigned char* data, size_t size);

#endif //FILE_UTILS_H
