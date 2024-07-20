#ifndef OPENSSL_WRAPPER_H
#define OPENSSL_WRAPPER_H

/*!
 * \addtogroup SUPnP
 *
 * \file openssl_wrapper.h
 *
 * \brief Header file for wrapping OpenSSL logics - required by SUPnP.
 *
 * \author Roman Koifman
 */
#include "UpnpGlobal.h" /* for UPNP_EXPORT_SPEC */
#include "upnpconfig.h"

#ifdef UPNP_ENABLE_OPEN_SSL

#include <openssl/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OPENSSL_SUCCESS (1)

#define OPENSSL_FAILURE (0)

/*!
 * \brief Load a public key from hex string.
 *
 * \note Remember to EVP_PKEY_free(loaded_public_key)
 *
 * \return EVP_PKEY* on success, NULL on failure.
 */
UPNP_EXPORT_SPEC EVP_PKEY * load_public_key_from_hex(const char* hex);

/*!
 * \brief Load a public key from PEM file.
 *
 * \note Remember to EVP_PKEY_free(loaded_public_key)
 *
 * \return EVP_PKEY* on success, NULL on failure.
 */
UPNP_EXPORT_SPEC EVP_PKEY * load_public_key_from_pem(const char* pem_file_path);

/*!
 * \brief Load a private key from PEM file.
 *
 * \note Remember to EVP_PKEY_free(loaded_public_key)
 *
 * \return EVP_PKEY* on success, NULL on failure.
 */
UPNP_EXPORT_SPEC EVP_PKEY * load_private_key_from_pem(const char* pem_file_path);

/*!
 * \brief Load a certificate from PEM file.
 *
 * \note Remember to Remember to X509_free(cert)
 *
 * \return X509 * certificate on success, NULL on failure.
 */
UPNP_EXPORT_SPEC X509 * load_certificate_from_pem(const char* pem_file_path);

/*!
 * \brief Load a certificate from hex string.
 *
 * \return OPENSSL_SUCCESS on success, OPENSSL_FAILURE on failure.
 */
UPNP_EXPORT_SPEC int verify_signature(const char* sig_name, EVP_PKEY *pkey, const char *hex_sig, const char *data);

/*!
 * \brief Verify certificate.
 *
 * \return OPENSSL_SUCCESS on success, OPENSSL_FAILURE on failure.
 */
UPNP_EXPORT_SPEC int verify_certificate(const char * cert_name, X509 *cert, EVP_PKEY *pkey);

/*!
 * \brief Initialize SUPnP secure layer.
 *
 * \return OPENSSL_SUCCESS on success, OPENSSL_FAILURE on failure.
 */
UPNP_EXPORT_SPEC int init_openssl_wrapper();

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* UPNP_ENABLE_OPEN_SSL */

#endif //OPENSSL_WRAPPER_H
