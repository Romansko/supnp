/*!
* \addtogroup SUPnP
 *
 * \file supnp.h
 *
 * \brief Header file for SUPnP secure layer method. Implementing logics from
 * the paper "Kayas, G., Hossain, M., Payton, J., & Islam, S. R. (2021). SUPnP:
 * Secure Access and Service Registration for UPnP-Enabled Internet of Things.
 * IEEE Internet of Things Journal, 8(14), 11561-11580."
 *
 * \author Roman Koifman
 */
#ifndef SUPNP_H
#define SUPNP_H

#include "UpnpGlobal.h" /* for UPNP_EXPORT_SPEC */
#include "upnpconfig.h"

#ifdef ENABLE_SUPNP

/* Forward decleration <openssl/types.h> */
typedef struct evp_pkey_st EVP_PKEY;
typedef struct x509_st X509;

#ifdef __cplusplus
extern "C" {
#endif


/* Forward declaration */
typedef struct cJSON cJSON; 

/*!
 * \name SUPnP Document keys
 *
 * @{
 */
#define SUPNP_DOC_TYPE        "TYPE"
#define SUPNP_DOC_NAME        "NAME"
#define SUPNP_DOC_PUBLIC_KEY  "PK"
#define SUPNP_DOC_SERVICES    "SERVICES"
#define SUPNP_DOC_SIG_OWNER   "SIG-OWNER"
#define SUPNP_DOC_SIG_UCA     "SIG-UCA"
#define SUPNP_DOC_SIG_CON     "SIG-VER-CON"   /* Signature Verification Conditions */
#define SUPNP_DOC_SIGNATURES  "SIGS"
#define SUPNP_HARDWARE_DESC   "HW"
#define SUPNP_SOFTWARE_DESC   "SW"
/* @} SUPnPDocumentkeys */

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

/* @} SUPnPErrorCodes */

/*!
 * \brief Initialize SUPnP secure layer.
 *
 * \return SUPNP_E_SUCCESS on success, SUPNP_E_INTERNAL_ERROR on failure.
 */
UPNP_EXPORT_SPEC int SUpnpInit();

/*!
 * \brief Verify DSD / SAD document.
 *
 * \return SUPNP_E_SUCCESS on success, SUPNP_E_INVALID_CERTIFICATE on failure.
 */
UPNP_EXPORT_SPEC int verify_supnp_document(const cJSON* supnp_document, EVP_PKEY * ca_pkey, X509 * uca_cert, X509 * device_cert);

/* Temporary function for testing */
UPNP_EXPORT_SPEC int test_supnp_ducuments();
UPNP_EXPORT_SPEC int test_nonce_encryption();
UPNP_EXPORT_SPEC void SUpnp_test_registration();
/**/

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */

#endif //SUPNP_H
