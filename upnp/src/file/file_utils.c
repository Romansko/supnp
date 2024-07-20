#include "file_utils.h"

#include <stdio.h>
#include <stdlib.h>

/**
 * Internal error logging macro
 */
#define file_error(...) \
{ \
	fprintf(stderr, "[File Utils Error] %s::%s(%d): ", __FILE__, __func__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); \
}

/**
 * Internal message logging macro
 */
#define file_log(...) \
{ \
	fprintf(stdout, "[File Utils]: "); \
	fprintf(stdout, __VA_ARGS__); \
}

/**
 * Internal verification macro
 * @param cond condition to check
 * @param ret return value on failure
 */
#define file_verify(cond, ret, ...) \
{ \
	if (!(cond)) { \
		file_error(__VA_ARGS__); \
		return ret; \
	} \
}

/**
 *
 * @param filepath given file path to read
 * @return
 */
char * read_file(const char* filepath, const char * mode)
{
	FILE* fp = fopen(filepath, mode);
	file_verify((fp != NULL), NULL, "Error opening file: %s\n", filepath);

	// Get the file size
	fseek(fp, 0, SEEK_END);
	long file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	// Allocate a buffer
	char* content = (char*)malloc(file_size + 1);
	file_verify((content != NULL), NULL, "Error allocating memory for file %s\n", filepath);

	// Read the file content
	size_t bytes_read = fread(content, file_size, 1, fp);
	fclose(fp);

	// Verify single chuck was read
	file_verify((bytes_read == 1), NULL, "Error reading file %s\n", filepath);

	return content; /* remember to free(content) */
}

