#include "file_utils.h"

#include <stdio.h>
#include <stdlib.h>

/**
 * Internal error logging macro
 */
#define file_error(...) { \
	fprintf(stderr, "[File Error] %s::%s(%d): ", __FILE__, __func__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); \
}

/**
 * Internal message logging macro
 */
#define file_log(...) { \
	fprintf(stdout, "[File Utils]: "); \
	fprintf(stdout, __VA_ARGS__); \
}

/**
 * Internal verification macro
 * @param test condition to check
 * @label label to jump to in case of failure
 */
#define file_verify(test, label, ...) { \
    if (!(test)) { \
        file_error(__VA_ARGS__); \
        goto label; \
    } \
}

/**
 * Free a ponter if it is not NULL.
 * @param ptr pointer to free
 */
#define file_freeif(ptr) { \
    if (ptr != NULL) { \
        free(ptr); \
        ptr = NULL; \
    } \
}

/**
 *
 * @param filepath given file path to read
 * @param mode file mode to open
 * @return
 */
char *read_file(const char *filepath, const char *mode)
{
    char *content = NULL;
    FILE *fp = fopen(filepath, mode);
    file_verify(fp != NULL, error, "Error opening file: %s\n", filepath);

    // Get the file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Allocate a buffer
    content = (char *)malloc(file_size + 1);
    file_verify(content != NULL,
        error,
        "Error allocating memory for file %s\n",
        filepath);

    // Read the file content
    const size_t bytes_read = fread(content, file_size, 1, fp);

    // Verify single chunck was read
    file_verify(bytes_read == 1, error, "Error reading file %s\n", filepath);
    goto success;

error:
    file_freeif(content);

success:
    if (fp) {
        fclose(fp);
        fp = NULL;
    }
    return content; /* remember to free(content) */
}

