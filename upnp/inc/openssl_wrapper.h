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

#include <stddef.h>

#ifdef UPNP_ENABLE_OPEN_SSL

#include <openssl/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OPENSSL_SUCCESS (1)

#define OPENSSL_FAILURE (0)

#define OPENSSL_CSPRNG_SIZE (32)  /* Default OpenSSL CSPRNG 256 bits */

/*!
 * \brief Initialize SUPnP secure layer.
 *
 * \return OPENSSL_SUCCESS on success, OPENSSL_FAILURE on failure.
 */
UPNP_EXPORT_SPEC int init_openssl_wrapper();

/*!
 * \brief print data as hex.
 */
UPNP_EXPORT_SPEC void print_as_hex(const unsigned char *data, int len);

/*!
 * \brief convert binary data to hex string.
 *
 * \note Remember to free the returned pointer.
 *
 * \return pointer on success, NULL on failure.
 */
UPNP_EXPORT_SPEC unsigned char * hex_string_to_binary(const char* hex, size_t * dsize);

/*!
 * \brief Load a public key from hex string.
 *
 * \note Remember to EVP_PKEY_free(loaded_public_key)
 *
 * \return EVP_PKEY* on success, NULL on failure.
 */
UPNP_EXPORT_SPEC EVP_PKEY * load_public_key_from_hex(const char* hex);

/*!
 * \brief Convert public key to bytes.
 *
 * \note Remember to free the return pointer.
 *
 * \return pointer to public key bytes on success, NULL on failure.
 */
UPNP_EXPORT_SPEC unsigned char * public_key_to_bytes(const EVP_PKEY *public_key, int* size);

/*!
 * \brief Convert private key to bytes.
 *
 * \note Remember to free the return pointer.
 *
 * \return pointer to private key bytes on success, NULL on failure.
 */
UPNP_EXPORT_SPEC unsigned char * private_key_to_bytes(const EVP_PKEY *private_key, int* size);

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
 * \brief Verify certificate.
 *
 * \return OPENSSL_SUCCESS on success, OPENSSL_FAILURE on failure.
 */
UPNP_EXPORT_SPEC int verify_certificate(const char * cert_name, X509 *cert, EVP_PKEY *pkey);

/*!
 * \brief Load a certificate from hex string.
 *
 * \return OPENSSL_SUCCESS on success, OPENSSL_FAILURE on failure.
 */
UPNP_EXPORT_SPEC int verify_signature(const char* sig_name, EVP_PKEY *pkey, const char *hex_sig, const unsigned char *data, const size_t dsize);

/*!
 * \brief Encrypt data
 *
 * \note Remember to free the returned pointer.
 *
 * \return pointer to encrypted data on success, NULL on failure.
 */
UPNP_EXPORT_SPEC unsigned char * encrypt_sym(const unsigned char * pkey, int * enc_size, const unsigned char * data, size_t dsize);

/*!
 * \brief Decrypt data
 *
 * \note Remember to free the returned pointer.
 *
 * \return pointer to decrypted data on success, NULL on failure.
 */
UPNP_EXPORT_SPEC unsigned char * decrypt_sym(const unsigned char * pkey, int * dec_size, const unsigned char * encrypted, size_t enc_size);

/*!
 * \brief Encrypt data using asymmetric key
 *
 * \note Remember to free the returned pointer.
 *
 * \return pointer to encrypted data on success, NULL on failure.
 */
UPNP_EXPORT_SPEC unsigned char * encrypt_asym(EVP_PKEY* pkey, size_t * enc_size, const unsigned char * data, size_t dsize);

/*!
 * \brief Decrypt data using asymmetric key
 *
 * \note Remember to free the returned pointer.
 *
 * \return pointer to decrypted data on success, NULL on failure.
 */
UPNP_EXPORT_SPEC unsigned char * decrypt_asym(EVP_PKEY* pkey, size_t * enc_size, const unsigned char * data, size_t dsize);

/*!
 * \brief Generate a nonce.
 *
 * \note Remember to free the returned nonce.
 *
 * \return a nonce on success, NULL on failure.
 */
UPNP_EXPORT_SPEC unsigned char * generate_nonce(size_t nonce_size);

/*!
 * \brief Calcualte SHA256 hash.
 *
 * \return OPENSSL_SUCCESS on success, OPENSSL_FAILURE on failure.
 */
int do_sha256(const unsigned char *data, size_t dsize, unsigned char hash[]);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* UPNP_ENABLE_OPEN_SSL */

#endif //OPENSSL_WRAPPER_H
