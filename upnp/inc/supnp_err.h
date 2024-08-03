#ifndef SUPNP_ERR_H
#define SUPNP_ERR_H

/*!
 * \addtogroup SUPnP
 *
 * \file supnp_err.h
 *
 * \brief Header file for SUPnP error codes.
 *
 * \author Roman Koifman
 */
#include "stdio.h"
#include "UpnpGlobal.h" /* for UPNP_EXPORT_SPEC */
#include "upnpconfig.h"

#ifdef ENABLE_SUPNP

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \name SUPnP Error codes
 *
 * The functions in the SDK API can return a variety of error
 * codes to describe problems encountered during execution.  This section
 * lists the error codes and provides a brief description of what each error
 * code means.  Refer to the documentation for each function for a
 * description of what an error code means in that context.
 *
 * @{
 */

/*!
 * \brief The operation completed successfully.
 *
 * For asynchronous functions, this only means that the packet generated by
 * the operation was successfully transmitted on the network.  The result of
 * the entire operation comes as part of the callback for that operation.
 */
#define SUPNP_E_SUCCESS (0)

/*!
 * \brief Generic error code for internal conditions not covered by other
 * error codes.
 */
#define SUPNP_E_INTERNAL_ERROR (-600)

/*!
 * \brief The function was passed an invalid argument.
 */
#define SUPNP_E_INVALID_ARGUMENT (-601)

/*!
 * \brief The filename passed to one of the device registration functions was
 * not found or was not accessible.
 */
#define SUPNP_E_FILE_NOT_FOUND (-602)

/*!
 * \brief The certificate is invalid.
 */
#define SUPNP_E_INVALID_CERTIFICATE (-603)

/*!
 * \brief The certificate is invalid.
 */
#define SUPNP_E_INVALID_SIGNATURE (-604)

/*!
 * \brief The DSD / SAD document is invalid.
 */
#define SUPNP_E_INVALID_DOCUMENT (-605)

/*!
 * \brief Test failed
 */
#define SUPNP_E_TEST_FAIL (-699)

/* @} SUPnPErrorCodes */

/**
 * Internal error logging macro
 */
#define supnp_error(...) { \
    fprintf(stderr, "[SUPnP Error] %s::%s(%d): ", __FILE__, __func__, __LINE__); \
    fprintf(stderr, __VA_ARGS__); \
 }


/**
 * Internal message logging macro
 */
#define supnp_log(...) { \
    fprintf(stdout, "[SUPnP]: "); \
    fprintf(stdout, __VA_ARGS__); \
 }

/**
 * Internal verification macro
 * @param test condition to check
 * @param label label to jump to in case of failure
 */
#define supnp_verify(test, label, ...) { \
    if (!(test)) { \
        supnp_error(__VA_ARGS__); \
        goto label; \
    } \
}


/**
 * Free a pointer if it is not NULL
 * @param ptr
 */
#define freeif(ptr) { \
    if (ptr != NULL) { \
        free(ptr); \
        ptr = NULL; \
    } \
}

/**
 * Free a ponter if it is not NULL with a given function
 * @param ptr pointer to free
 * @param func function to free pointer
 */
#define freeif2(ptr, free_func) { \
    if (ptr != NULL) { \
        free_func(ptr); \
        ptr = NULL; \
    } \
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */

#endif //SUPNP_ERR_H
