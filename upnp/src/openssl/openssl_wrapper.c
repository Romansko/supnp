/*!
 * \addtogroup SUPnP
 *
 * \file openssl_wrapper.c
 *
 * \brief source file for wrapping OpenSSL logics - required by SUPnP.
 * developed with libssl-dev v3.0
 * https://www.openssl.org/docs/man3.0/index.html
 *
 * \author Roman Koifman
 */
#include "upnpconfig.h"

#ifdef UPNP_ENABLE_OPEN_SSL

#include "openssl_wrapper.h"
#include "file_utils.h"
#include <openssl/ssl.h>     /* OpenSSL Library Init */
#include <openssl/rand.h>    /* RAND_bytes */
#include <openssl/err.h>     /* Open SSL Error string & code */
#include <openssl/pem.h>     /* PEM related */
#include <openssl/evp.h>     /* EVP related */
#include <openssl/sha.h>     /* For SHA256  */

#ifdef __cplusplus
extern "C" {
#endif

// Obviously change in your apps..
const unsigned char * IV = "SUPNP_CHANGE_IV!"; /* 16 bytes IV for AES-256-CBC */

/**
 * Returns the last OpenSSL error. No free is required.
 * Make sure SUpnpInit() was called before.
 */
const char * get_openssl_last_error()
{
	const char * err = ERR_error_string(ERR_get_error(), NULL);
	ERR_clear_error();
	return err;
}

/**
 * Internal error logging macro
 */
#define sslwrapper_error(...) { \
	fprintf(stderr, "[SSL_W Error] %s::%s(%d): ", __FILE__, __func__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); \
	fprintf(stderr, "\t%s\n", get_openssl_last_error()); \
}

/**
 * Internal message logging macro
 */
#define sslwrapper_log(...) { \
	fprintf(stdout, "[SSL_W]: "); \
	fprintf(stdout, __VA_ARGS__); \
}

/**
 * Internal verification macro
 * @param test condition to check
 * @note must define 'cleanup' label within function.
 */
#define sslwrapper_verify(test, ...) { \
	if (!(test)) { \
		sslwrapper_error(__VA_ARGS__); \
		goto cleanup; \
	} \
}

/**
 * Free a ponter if it is not NULL with a given function
 * @param ptr pointer to free
 * @param free_func function to free pointer
 */
#define wrapper_freeif(ptr, free_func) { \
    if (ptr != NULL) \
        free_func(ptr); \
        ptr = NULL; \
}

/**
 * Initialize SUPnP secure layer.
 * @return OPENSSL_SUCCESS on success, OPENSSL_FAILURE on failure.
 */
int init_openssl_wrapper()
{
	sslwrapper_log("Initializing OpenSSL Wrapper..\n");
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	return OPENSSL_SUCCESS;
}

/**
 * Print binary data as hex.
 * @param data binary data
 * @param len data length
 */
void print_as_hex(const unsigned char *data, const int len)
{
	if (data == NULL)
		return;
	for (size_t i = 0; i < len; ++i) {
		printf("%02x", data[i]);
	}
	printf("\n");
}

/**
 * Convert a hex string to binary.
 * @param hex a hex string
 * @param dsize the size of the returned binary data
 * @return a binary representation of the hex string
 */
unsigned char * hex_string_to_binary(const char* hex, size_t * dsize)
{
    unsigned char* binary = NULL;
    sslwrapper_verify(hex != NULL, "NULL hex string provided.\n");
	sslwrapper_verify(dsize != NULL, "NULL data size ptr.\n");
	const size_t hex_len = strlen(hex);
	*dsize = hex_len / 2;
	sslwrapper_verify((*dsize % 2 == 0) && (*dsize > 0), "Invalid hex string length.\n");
	binary = malloc(*dsize);
    sslwrapper_verify(binary != NULL, "Error allocating memory for binary data.\n");
	for (size_t i = 0; i < hex_len; i += 2)
	{
		sscanf(hex + i, "%2hhx", &binary[i / 2]);
	}
cleanup:
	return binary; /* remember to free(binary); */
}


/**
 * Load a public key from a hex string.
 * The caller is responsible for freeing the public key.
 * @param hex a hex string representing a public key
 * @return a EVP_PKEY * public key on success, NULL on failure
 */
EVP_PKEY * load_public_key_from_hex(const char* hex)
{
	EVP_PKEY* pubkey = NULL;
	size_t dsize = 0;
	unsigned char * bin = hex_string_to_binary(hex, &dsize);
	sslwrapper_verify(bin != NULL, "Error converting public key hex string.\n");
	const unsigned char * bin_copy = bin;
	pubkey = d2i_PUBKEY(NULL, &bin_copy, dsize);  /* Use SubjectPublicKeyInfo format */
	free(bin);
	sslwrapper_verify(pubkey != NULL, "Error loading public key\n");
cleanup:
	return pubkey; /* Remember to EVP_PKEY_free(pubkey); */
}


/**
 * Convert a public key to bytes.
 * The caller is responsible for freeing the return pointer.
 * @param public_key a public key
 * @param size a pointer to an integer to store the size of the returned buffer
 * @return a pointer to the public key bytes on success, NULL on failure
 */
unsigned char * public_key_to_bytes(const EVP_PKEY *public_key, int* size)
{
    unsigned char * buffer = NULL;
    sslwrapper_verify(public_key != NULL, "Empty public key provided.\n");
	*size = i2d_PUBKEY(public_key, &buffer);
	sslwrapper_verify((*size > 0) && (buffer != NULL), "Error converting public key to bytes.\n");
cleanup:
	return buffer; /* remember to free(buffer); */
}

/**
 * Convert a private key to bytes.
 * The caller is responsible for freeing the return pointer.
 * @param private_key a private key
 * @param size a pointer to an integer to store the size of the returned buffer
 * @return a pointer to the private key bytes on success, NULL on failure
 */
unsigned char * private_key_to_bytes(const EVP_PKEY *private_key, int* size)
{
    unsigned char * buffer = NULL;
    sslwrapper_verify(private_key != NULL, "Empty private key provided.\n");
	*size = i2d_PrivateKey(private_key, &buffer);
	sslwrapper_verify((*size > 0) && (buffer != NULL), "Error converting private key to bytes.\n");
cleanup:
	return buffer; /* remember to free(buffer); */
}


/**
 * Load a public key from a PEM file.
 * The caller is responsible for freeing the public key.
 * @param pem_file_path a path to a PEM file
 * @return a EVP_PKEY * public key on success, NULL on failure
 */
EVP_PKEY * load_public_key_from_pem(const char* pem_file_path)
{
    EVP_PKEY* loaded_key = NULL;
    FILE* fp = NULL;
	macro_file_open(fp, pem_file_path, "r", NULL);
	loaded_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	fclose(fp);
	sslwrapper_verify(loaded_key != NULL, "Error loading public key from PEM file %s\n", pem_file_path);
cleanup:
	return loaded_key; /* Remember to EVP_PKEY_free(loaded_key); */
}

/**
 * Load a private key from a PEM file.
 * The caller is responsible for freeing the private key.
 * @param pem_file_path a path to a PEM file
 * @return a EVP_PKEY * private key on success, NULL on failure
 */
EVP_PKEY * load_private_key_from_pem(const char* pem_file_path)
{
    EVP_PKEY* loaded_key = NULL;
    FILE* fp = NULL;
	macro_file_open(fp, pem_file_path, "r", NULL);
	loaded_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	sslwrapper_verify(loaded_key != NULL, "Error loading private key from PEM file %s\n", pem_file_path);
cleanup:
	return loaded_key; /* Remember to EVP_PKEY_free(loaded_key); */
}

/**
 * Load a certificate from a PEM file.
 * The caller is responsible for freeing the certificate.
 * @param pem_file_path a path to a PEM file
 * @return a X509 * certificate on success, NULL on failure
 */
X509 * load_certificate_from_pem(const char* pem_file_path)
{
    X509* cert = NULL;
    FILE* fp = NULL;
	macro_file_open(fp, pem_file_path, "r", NULL);
	cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);
	sslwrapper_verify(cert != NULL, "Error loading certificate from PEM file %s\n", pem_file_path);
cleanup:
	return cert; /* Remember to X509_free(cert); */
}

/**
 * Verify certificate.
 * todo: Should use X509_verify_cert instead of X509_verify ?
 * @param cert_name Certificate's name
 * @param cert a certificate
 * @param pkey a public key corresponding to the entity that signed the certificate
 * @return OPENSSL_SUCCESS on success, OPENSSL_FAILURE on failure.
 */
int verify_certificate(const char * cert_name, X509 *cert, EVP_PKEY *pkey)
{
	int ret = OPENSSL_FAILURE;
	sslwrapper_log("Verifying '%s''s certificate..\n", cert_name);
	sslwrapper_verify(cert != NULL, "Empty certificate provided.\n");
	sslwrapper_verify(pkey != NULL, "Empty CA public key provided.\n");
	ret = X509_verify(cert, pkey);
	sslwrapper_verify(ret == OPENSSL_SUCCESS, "verification error\n");
	sslwrapper_log("'%s''s certificate is valid.\n", cert_name);
cleanup:
	return ret;
}

/**
 * Verify signature.
 * @param sig_name Signature's name
 * @param pkey a public key corresponding to the entity that signed the data
 * @param hex_sig a hex string representing the signature
 * @param data the data that was signed
 * @param dsize the size of the data
 * @return OPENSSL_SUCCESS on success, OPENSSL_FAILURE on failure.
 */
int verify_signature(const char* sig_name, EVP_PKEY *pkey, const char *hex_sig, const unsigned char *data, const size_t dsize)
{
    int ret = OPENSSL_FAILURE;
    EVP_MD_CTX *ctx = NULL;
	size_t sig_size = 0;
	sslwrapper_log("Verifying '%s''s signature..\n", sig_name);

	// Arguments Verification
	sslwrapper_verify(pkey != NULL, "NULL public key provided.\n");
	sslwrapper_verify(hex_sig != NULL, "NULL signature provided.\n");
	sslwrapper_verify(data != NULL, "NULL data provided.\n");
	sslwrapper_verify(dsize > 0, "Invalid data size provided.\n");

	// Initialize context
	ctx = EVP_MD_CTX_new();
	sslwrapper_verify(ctx != NULL, "'%s': Error creating EVP_MD_CTX.\n", sig_name);
	ret = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey);
	sslwrapper_verify(ret == OPENSSL_SUCCESS, "'%s':", sig_name);
	ret = EVP_DigestVerifyUpdate(ctx, data, dsize);
	sslwrapper_verify(ret == OPENSSL_SUCCESS, "'%s':", sig_name);
	unsigned char * sig = hex_string_to_binary(hex_sig, &sig_size);
	sslwrapper_verify(sig != NULL, "Failed to convert hex signature to bytes.\n");

	// Verify signature
	ret = EVP_DigestVerifyFinal(ctx, sig, (strlen(hex_sig)/2));
    sslwrapper_verify(ret == OPENSSL_SUCCESS, "'%s':", sig_name);

cleanup:
    wrapper_freeif(ctx, EVP_MD_CTX_free);
    wrapper_freeif(sig, free);

	return ret;
}

/**
 * Encrypt data using symmetric key.
 * The caller is responsible for freeing the return pointer.
 * @param pkey a symmetric key
 * @param enc_size a pointer to an integer to store the size of the returned buffer
 * @param data the data to encrypt
 * @param dsize the size of the data
 * @return a pointer to the encrypted data on success, NULL on failure
 * @note The IV is hardcoded in this function.
 */
unsigned char * encrypt_sym(const unsigned char * pkey, int * enc_size, const unsigned char * data, size_t dsize)
{
	unsigned char * encrypted = NULL;
	EVP_CIPHER_CTX* ctx = NULL;
	int final_len = 0;  /* Only for final stage encyption */
	unsigned char buffer[1024];

	// Verify Key
	sslwrapper_verify(pkey != NULL, "Empty private key provided.\n");

	// Initialize context
	ctx = EVP_CIPHER_CTX_new();
	sslwrapper_verify(ctx != NULL, "Error creating EVP_CIPHER_CTX.\n");
	sslwrapper_verify(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, pkey, IV) == OPENSSL_SUCCESS, "Encryption error.\n");

	// Encryption
	*enc_size = 0;
	sslwrapper_verify(EVP_EncryptUpdate(ctx, buffer, enc_size, data, dsize) == OPENSSL_SUCCESS, "Encryption error.\n");
	sslwrapper_verify(EVP_EncryptFinal_ex(ctx, (buffer + *enc_size), &final_len) == OPENSSL_SUCCESS, "Encryption error.\n");
	*enc_size += final_len;

	// allocate memory for the encrypted data
	sslwrapper_verify(*enc_size > 0, "Encryption error.\n");
	encrypted = malloc(*enc_size);
	sslwrapper_verify(encrypted != NULL, "Error allocating memory for encrypted data.\n");
	memcpy(encrypted, buffer, *enc_size);

cleanup:
    wrapper_freeif(ctx, EVP_CIPHER_CTX_free);
	return encrypted;
}


/**
 * Decrypt data using symmetric key.
 * The caller is responsible for freeing the return pointer.
 * @param pkey a symmetric key
 * @param dec_size a pointer to an integer to store the size of the returned buffer
 * @param encrypted the data to decrypt
 * @param enc_size the size of the data
 * @return a pointer to the decrypted data on success, NULL on failure
 * @note The IV is hardcoded in this function.
 */
unsigned char * decrypt_sym(const unsigned char * pkey, int * dec_size, const unsigned char * encrypted, size_t enc_size)
{
	unsigned char * decrypted = NULL;
	EVP_CIPHER_CTX* ctx = NULL;
	int final_len = 0;  /* Only for final stage decryption */
	unsigned char buffer[1024];

	// Verify Key
	sslwrapper_verify(pkey != NULL, "Empty private key provided.\n");

	// Initialize context
	ctx = EVP_CIPHER_CTX_new();
	sslwrapper_verify(ctx != NULL, "Error creating EVP_CIPHER_CTX.\n");
	sslwrapper_verify(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, pkey, IV) == OPENSSL_SUCCESS, "Decryption error.\n");

	// Decryption
	*dec_size = 0;
	sslwrapper_verify(EVP_DecryptUpdate(ctx, buffer, dec_size, encrypted, enc_size) == OPENSSL_SUCCESS, "Decryption error.\n");
	sslwrapper_verify(EVP_DecryptFinal_ex(ctx, buffer + *dec_size, &final_len) == OPENSSL_SUCCESS, "Decryption error.\n");
	*dec_size += final_len;
	EVP_CIPHER_CTX_free(ctx);

	// Allocate memory for the decrypted data
	sslwrapper_verify(*dec_size > 0, "Decryption error.\n");
	decrypted = malloc(*dec_size);
	sslwrapper_verify(decrypted != NULL, "Error allocating memory for decrypted data.\n");
	memcpy(decrypted, buffer, *dec_size);

cleanup:
    wrapper_freeif(ctx, EVP_CIPHER_CTX_free);
	return decrypted;
}

/**
 * Encrypt data using asymmetric key.
 * The caller is responsible for freeing the returned pointer.
 * @param pkey a public key
 * @param enc_size a pointer to a size_t to store the size of the returned buffer
 * @param data the data to encrypt
 * @param dsize the size of the data
 * @return a pointer to the encrypted data on success, NULL on failure
 * @note implemented according to https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_encrypt.html
 */
unsigned char * encrypt_asym(EVP_PKEY* pkey, size_t * enc_size, const unsigned char * data, const size_t dsize)
{
	EVP_PKEY_CTX *ctx = NULL;
	unsigned char * encrypted = NULL;

	// verify arguments
	sslwrapper_verify(pkey != NULL, "NULL key provided.\n");
	sslwrapper_verify(enc_size != NULL, "NULL enc_size provided.\n");
	sslwrapper_verify(data != NULL, "NULL data provided.\n");
	sslwrapper_verify(dsize > 0, "Invalid data size provided.\n");
	*enc_size = 0;

	// Initialize context
	ctx = EVP_PKEY_CTX_new(pkey, NULL);  // eng = NULL ->start with the default OpenSSL RSA implementation
	sslwrapper_verify(ctx != NULL, "Error creating EVP_PKEY_CTX.\n");
	sslwrapper_verify(EVP_PKEY_encrypt_init(ctx) == OPENSSL_SUCCESS, "Encryption init error.\n");
	sslwrapper_verify(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) == OPENSSL_SUCCESS, "Set padding error.\n");

	// retrieve the encryption size & allocate memory
	sslwrapper_verify(EVP_PKEY_encrypt(ctx, NULL, enc_size, data, dsize) == OPENSSL_SUCCESS, "Unable to retrieve encryption length.\n");
	encrypted = malloc(*enc_size);
	sslwrapper_verify(encrypted != NULL, "Error allocating memory for encrypted data.\n");

	// Encrypt data
	sslwrapper_verify(EVP_PKEY_encrypt(ctx, encrypted, enc_size, data, dsize) == OPENSSL_SUCCESS, "Encryption error.\n");
    goto success;

cleanup:
    wrapper_freeif(encrypted, free);

success:
    wrapper_freeif(ctx, EVP_PKEY_CTX_free);
	return encrypted;
}

/**
 * Decrypt data using asymmetric key.
 * The caller is responsible for freeing the returned pointer.
 * @param pkey a private key
 * @param enc_size a pointer to a size_t to store the size of the returned buffer
 * @param data the data to decrypt
 * @param dsize the size of the data
 * @return a pointer to the decrypted data on success, NULL on failure
 * @note implemented according to https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_decrypt.html
 */
unsigned char * decrypt_asym(EVP_PKEY* pkey, size_t * enc_size, const unsigned char * data, const size_t dsize)
{
	EVP_PKEY_CTX *ctx = NULL;
	unsigned char * decrypted = NULL;

	// verify arguments
	sslwrapper_verify(pkey != NULL, "NULL key provided.\n");
	sslwrapper_verify(enc_size != NULL, "NULL enc_size provided.\n");
	sslwrapper_verify(data != NULL, "NULL data provided.\n");
	sslwrapper_verify(dsize > 0, "Invalid data size provided.\n");
	*enc_size = 0;

	// Initialize context
	ctx = EVP_PKEY_CTX_new(pkey, NULL);  // eng = NULL ->start with the default OpenSSL RSA implementation
	sslwrapper_verify(ctx != NULL, "Error creating EVP_PKEY_CTX.\n");
	sslwrapper_verify(EVP_PKEY_decrypt_init(ctx) == OPENSSL_SUCCESS, "Decryption init error.\n");
	sslwrapper_verify(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) == OPENSSL_SUCCESS, "Set padding error.\n");

	// retrieve the decryption size & allocate memory
	sslwrapper_verify(EVP_PKEY_decrypt(ctx, NULL, enc_size, data, dsize) == OPENSSL_SUCCESS, "Unable to retrieve decryption length.\n");
	decrypted = malloc(*enc_size);
	sslwrapper_verify(decrypted != NULL, "Error allocating memory for decrypted data.\n");

	// Decrypt data
	sslwrapper_verify(EVP_PKEY_decrypt(ctx, decrypted, enc_size, data, dsize) == OPENSSL_SUCCESS, "Decryption error.\n");
    goto success;

cleanup:
    wrapper_freeif(decrypted, free);

success:
    wrapper_freeif(ctx, EVP_PKEY_CTX_free);
	return decrypted;
}

/**
 * Generate a nonce.
 * The caller is responsible for freeing the nonce.
 * @param nonce_size the size of the requested nonce
 * @return a nonce on success, NULL on failure
 */
unsigned char * generate_nonce(const size_t nonce_size)
{
	unsigned char * nonce = NULL;

	// Allocate memory
	nonce = malloc(nonce_size);
	sslwrapper_verify(nonce != NULL, "Error allocating memory for nonce.\n");

	// Generate random bytes for nonce
	sslwrapper_verify(RAND_bytes(nonce, OPENSSL_CSPRNG_SIZE) == OPENSSL_SUCCESS, "Error generating random nonce.\n");
    goto success;

cleanup:
    wrapper_freeif(nonce, free);

success:
	return nonce;
}

/**
 * Calculate SHA256 hash.
 * @param data the data to hash
 * @param dsize the size of the data
 * @param hash the calculated hash
 * @return OPENSSL_SUCCESS on success, OPENSSL_FAILURE on failure
 * @note https://www.openssl.org/docs/man3.0/man3/SHA256.html
 */
int do_sha256(const unsigned char *data, const size_t dsize, unsigned char hash[SHA256_DIGEST_LENGTH])
{
    int ret = OPENSSL_FAILURE;
	sslwrapper_verify(data != NULL, "Empty data provided.\n");
	sslwrapper_verify(dsize > 0, "Invalid data size.\n");
	(void) SHA256(data, dsize, hash);
    ret = OPENSSL_SUCCESS;
cleanup:
    return ret;
}


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* UPNP_ENABLE_OPEN_SSL */