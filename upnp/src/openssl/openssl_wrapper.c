/*!
 * \addtogroup SUPnP
 *
 * \file openssl_wrapper.c
 *
 * \brief source file for wrapping OpenSSL logics - required by SUPnP.
 *
 * \author Roman Koifman
 */
#include "upnpconfig.h"

#ifdef UPNP_ENABLE_OPEN_SSL

#include "openssl_wrapper.h"
#include "supnp_err.h"


#include "file_utils.h"
#include <openssl/ssl.h>     /* OpenSSL Library Init */
#include <openssl/rand.h>    /* RAND_bytes */
#include <openssl/err.h>     /* Open SSL Error string & code */
#include <openssl/pem.h>     /* PEM related */
#include <openssl/evp.h>     /* EVP related */

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Internal error logging macro
 */
#define sslwrapper_error(...) { \
	fprintf(stderr, "[OpenSSL_W Error] %s::%s(%d): ", __FILE__, __func__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); \
}

/**
 * Internal message logging macro
 */
#define sslwrapper_log(...) { \
	fprintf(stdout, "[OpenSSL_W]: "); \
	fprintf(stdout, __VA_ARGS__); \
}

/**
 * Internal verification macro
 * @param cleaner cleanup function. Leave Empty if no cleanup is required.
 * @param cond condition to check
 * @param ret return value on failure
 */
#define sslwrapper_verify(cleaner, cond, ret, ...) { \
	if (!(cond)) { \
		sslwrapper_error(__VA_ARGS__); \
		cleaner; \
		return ret; \
	} \
}

/**
 * Initialize SUPnP secure layer.
 * @return OPENSSL_SUCCESS on success, OPENSSL_FAILURE on failure.
 */
int init_openssl_wrapper()
{
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	return OPENSSL_SUCCESS;
}

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
 * Convert a hex string to binary.
 * @param hex a hex string
 * @return a binary representation of the hex string
 */
unsigned char * hex_string_to_binary(const char* hex)
{
	sslwrapper_verify(, (hex != NULL), NULL, "Empty hex string provided.\n");
	const size_t hex_len = strlen(hex);
	const size_t bin_len = hex_len / 2;
	sslwrapper_verify(,(hex_len % 2) == 0, NULL, "Invalid hex string length.\n");
	unsigned char* binary = malloc(bin_len);
	for (size_t i = 0; i < hex_len; i += 2)
	{
		sscanf(hex + i, "%2hhx", &binary[i / 2]);
	}
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
	unsigned char * bin = hex_string_to_binary(hex);
	sslwrapper_verify(,bin, NULL, "Error converting public key hex string.\n");
	const unsigned char * bin_copy = bin;
	pubkey = d2i_PUBKEY(NULL, &bin_copy, strlen(hex) / 2);  /* Use SubjectPublicKeyInfo format */
	free(bin);
	sslwrapper_verify(, (pubkey), NULL, "%s\n", get_openssl_last_error());
	return pubkey; /* Remember to EVP_PKEY_free(pubkey); */
}


/**
 * Load a public key from a PEM file.
 * The caller is responsible for freeing the public key.
 * @param pem_file_path a path to a PEM file
 * @return a EVP_PKEY * public key on success, NULL on failure
 */
EVP_PKEY * load_public_key_from_pem(const char* pem_file_path)
{
	FILE* fp = NULL;
	EVP_PKEY* loaded_key = NULL;
	macro_file_open(fp, pem_file_path, "r", NULL);
	loaded_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	fclose(fp);
	sslwrapper_verify(,(loaded_key != NULL), NULL, "Error loading public key from PEM file %s\n", pem_file_path);
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
	FILE* fp = NULL;
	EVP_PKEY* loaded_key = NULL;
	macro_file_open(fp, pem_file_path, "r", NULL);
	loaded_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	sslwrapper_verify(,(loaded_key != NULL), NULL, "Error loading private key from PEM file %s\n", pem_file_path);
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
	FILE* fp = NULL;
	X509* cert = NULL;
	macro_file_open(fp, pem_file_path, "r", NULL);
	cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);
	sslwrapper_verify(,(cert != NULL), NULL, "Error loading certificate from PEM file %s\n", pem_file_path);
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
	int ret;
	sslwrapper_log("Verifying '%s''s certificate..\n", cert_name);
	sslwrapper_verify(, (cert != NULL),  OPENSSL_FAILURE, "Empty certificate provided.\n");
	sslwrapper_verify(, (pkey != NULL),  OPENSSL_FAILURE, "Empty CA public key provided.\n");
	ret = X509_verify(cert, pkey);
	sslwrapper_verify(, (ret == OPENSSL_SUCCESS), ret, "%s\n", get_openssl_last_error());
	sslwrapper_log("'%s''s certificate is valid.\n", cert_name);
	return ret;
}

int verify_signature(const char* sig_name, EVP_PKEY *pkey, const char *hex_sig, const char *data)
{
	int ret;
	sslwrapper_log("Verifying '%s''s signature..\n", sig_name);
	sslwrapper_verify(, (pkey != NULL), OPENSSL_FAILURE, "Empty public key provided.\n");
	sslwrapper_verify(, (hex_sig != NULL),  OPENSSL_FAILURE, "Empty signature provided.\n");
	sslwrapper_verify(, (data != NULL), OPENSSL_FAILURE, "Empty data provided.\n");
	const size_t dsize = strlen(data);
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	sslwrapper_verify(, ctx, OPENSSL_FAILURE, "'%s': Error creating EVP_MD_CTX.\n", sig_name);
	ret = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey);
	sslwrapper_verify(EVP_MD_CTX_free(ctx), (ret == OPENSSL_SUCCESS), ret, "'%s': %s\n", sig_name, get_openssl_last_error());
	ret = EVP_DigestVerifyUpdate(ctx, data, dsize);
	sslwrapper_verify(EVP_MD_CTX_free(ctx), (ret == OPENSSL_SUCCESS), ret, "'%s': %s\n", sig_name, get_openssl_last_error());
	unsigned char * sig = hex_string_to_binary(hex_sig);
	sslwrapper_verify(EVP_MD_CTX_free(ctx), (sig != NULL), OPENSSL_FAILURE, "Failed to convert hex signature to bytes.\n");
	ret = EVP_DigestVerifyFinal(ctx, sig, (strlen(hex_sig)/2));
	free(sig);
	EVP_MD_CTX_free(ctx);
	sslwrapper_verify(, (ret == OPENSSL_SUCCESS), ret, "'%s': %s\n", sig_name, get_openssl_last_error());
	return ret;
}


void generate_nonce_challenge(EVP_PKEY *public_key) 
{
	unsigned char nonce[32];  // Default OpenSSL CSPRNG 256bits
	sslwrapper_verify(, (RAND_bytes(nonce, sizeof(nonce)) == OPENSSL_SUCCESS),, "Error generating random nonce.\n");

	// Encrypt the nonce using the public key
	// (You'll need to implement this part based on your specific use case)

	// Print the nonce (for demonstration purposes)
	printf("Generated nonce: ");
	for (int i = 0; i < sizeof(nonce); ++i) {
		printf("%02x", nonce[i]);
	}
	printf("\n");
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* UPNP_ENABLE_OPEN_SSL */