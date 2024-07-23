/*!
 * \addtogroup SUPnP
 *
 * \file supnp.c
 *
 * \brief source file for SUPnP secure layer method. Implementing logics from
 * the paper "Kayas, G., Hossain, M., Payton, J., & Islam, S. R. (2021). SUPnP:
 * Secure Access and Service Registration for UPnP-Enabled Internet of Things.
 * IEEE Internet of Things Journal, 8(14), 11561-11580."
 *
 * \author Roman Koifman
 */
#include "stdio.h"
#include "upnpconfig.h"

#ifdef ENABLE_SUPNP
#include "supnp.h"
#include "supnp_err.h"
#include "file_utils.h"
#include <cJSON/cJSON.h>
#include "openssl_wrapper.h"

// todo: refactor to openssl_wrapper
#include <openssl/x509.h>
//

#ifdef __cplusplus
extern "C" {
#endif

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
 * @param cleaner cleanup function. Leave Empty if no cleanup is required.
 * @param cond condition to check
 * @param ret return value on failure
 */
#define supnp_verify(cleaner, cond, ret, ...) { \
	if (!(cond)) { \
		supnp_error(__VA_ARGS__); \
		cleaner; \
		return ret; \
	} \
}

#define supnp_extract_json_string(cleaner, doc, key, value) \
{ \
	value = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(doc, key)); \
	supnp_verify(cleaner, value, SUPNP_E_INVALID_DOCUMENT, "Unexpected '%s'\n", key); \
}

void freeif(void* ptr)
{
	if (ptr)
		free(ptr);
}

/**
 * Initialize SUPnP secure layer.
 * @return SUPNP_E_SUCCESS on success, SUPNP_E_INTERNAL_ERROR on failure.
 */
int SUpnpInit()
{
	supnp_log("Initializing SUPnP secure layer.\n");
	int ret = init_openssl_wrapper();
	supnp_verify(, (ret == OPENSSL_SUCCESS), ret, "Error initializing OpenSSL.\n");
	return SUPNP_E_SUCCESS;
}


/**
 * Verify SUPnP document (DSD/ SAD).
 * @param supnp_document a cJSON object representing the SUPnP document
 * @param ca_pkey CA public key
 * @param uca_cert UCA certificate
 * @param device_cert Device certificate
 * @return SUPNP_E_SUCCESS on success, SUPNP_E_INVALID_CERTIFICATE on failure.
 */
int verify_supnp_document(const cJSON* supnp_document, EVP_PKEY * ca_pkey, X509 * uca_cert, X509 * device_cert)
{
	int ret = SUPNP_E_SUCCESS;
	int x, y;
	char * device_name = NULL;
	char * device_type = NULL;
	char * in_doc_pkey = NULL;  /* Device public key within the document */
	char * sig_ver_con = NULL;  /* Signatures Verification Conditions */
	EVP_PKEY * pkey = NULL;

	/* Arguments Verification */
	supnp_verify(, (supnp_document != NULL), SUPNP_E_INVALID_ARGUMENT, "Empty DSD / SAD document provided\n");
	supnp_verify(, (ca_pkey != NULL),        SUPNP_E_INVALID_ARGUMENT, "Empty CA public key provided\n");
	supnp_verify(, (uca_cert != NULL),       SUPNP_E_INVALID_ARGUMENT, "Empty UCA Certificate provided\n");
	supnp_verify(, (device_cert != NULL),    SUPNP_E_INVALID_ARGUMENT, "Empty Device Certificate provided\n");

	/* Read SUPnP document name & type */
	supnp_extract_json_string(, supnp_document, SUPNP_DOC_NAME, device_name);
	supnp_extract_json_string(, supnp_document, SUPNP_DOC_TYPE, device_type);
	supnp_log("Verifying '%s' document. Type: '%s'.\n", device_name, device_type);

	/* Verify UCA Certificate */
	supnp_verify(, (verify_certificate("UCA", uca_cert, ca_pkey) == OPENSSL_SUCCESS), SUPNP_E_INVALID_CERTIFICATE, "Invalid UCA Certificate\n");

	/* Extract UCA Public Key && Verify Device Certificate */
	EVP_PKEY * uca_pk = X509_get_pubkey(uca_cert);
	supnp_verify(EVP_PKEY_free(uca_pk), (verify_certificate(device_name, device_cert, uca_pk) == OPENSSL_SUCCESS), SUPNP_E_INVALID_CERTIFICATE, "Invalid Device Certificate.\n");

	/* Extract Device Public Key */
	EVP_PKEY * device_pkey = X509_get_pubkey(device_cert);

	/* Verify Device Public Key */
	supnp_extract_json_string(EVP_PKEY_free(uca_pk), supnp_document, SUPNP_DOC_PUBLIC_KEY, in_doc_pkey);
	EVP_PKEY * doc_pk = load_public_key_from_hex(in_doc_pkey);
	supnp_verify(EVP_PKEY_free(uca_pk), (doc_pk), SUPNP_E_INVALID_DOCUMENT, "Error loading public key from '%s'.\n", SUPNP_DOC_PUBLIC_KEY);
	ret = EVP_PKEY_eq(doc_pk, device_pkey);
	EVP_PKEY_free(doc_pk);  // Not required anymore
	supnp_verify(EVP_PKEY_free(uca_pk); EVP_PKEY_free(device_pkey), (ret == OPENSSL_SUCCESS), SUPNP_E_INVALID_DOCUMENT, "Document's device public key doesn't match Device ceretificate's public key.\n");

	/* Retrieve signature verification conditions */
	supnp_extract_json_string(EVP_PKEY_free(uca_pk); EVP_PKEY_free(device_pkey), supnp_document, SUPNP_DOC_SIG_CON, sig_ver_con);
	ret = sscanf(sig_ver_con, "%d-of-%d", &x, &y);
	supnp_verify(EVP_PKEY_free(uca_pk); EVP_PKEY_free(device_pkey), (ret == 2), SUPNP_E_INVALID_DOCUMENT, "Error parsing Signature Verification Conditions '%s'.\n", SUPNP_DOC_SIG_CON);
	supnp_verify(EVP_PKEY_free(uca_pk); EVP_PKEY_free(device_pkey), (x >= 0 && y >= 0 && x <= y), SUPNP_E_INVALID_DOCUMENT, "Invalid Signature Verification Conditions '%s'.\n", SUPNP_DOC_SIG_CON);
	supnp_log("Signature Verification Conditions: %d-of-%d\n", x, y);

	/* Retrieve Signatures */
	const cJSON* sigs = cJSON_GetObjectItemCaseSensitive(supnp_document, SUPNP_DOC_SIGNATURES);
	supnp_verify(EVP_PKEY_free(uca_pk); EVP_PKEY_free(device_pkey), cJSON_IsArray(sigs), SUPNP_E_INVALID_DOCUMENT, "Unexpected '%s'\n", SUPNP_DOC_SIGNATURES);
	supnp_verify(EVP_PKEY_free(uca_pk); EVP_PKEY_free(device_pkey), (cJSON_GetArraySize(sigs) == y), SUPNP_E_INVALID_DOCUMENT, "Unexpected number of signatures in '%s'\n", SUPNP_DOC_SIGNATURES);
	if (x == 0) {
		EVP_PKEY_free(uca_pk);
		EVP_PKEY_free(device_pkey);
		supnp_log("Signatures verification is not required.\n");
		return SUPNP_E_SUCCESS;
	}

	/* Delete signatures from document, leaving only the content. */
	cJSON * doc_content = cJSON_Duplicate(supnp_document, 1);
	cJSON_DeleteItemFromObjectCaseSensitive(doc_content, SUPNP_DOC_SIG_OWNER);
	cJSON_DeleteItemFromObjectCaseSensitive(doc_content, SUPNP_DOC_SIG_UCA);
	char * data = cJSON_PrintUnformatted(doc_content);
	/* Verify Signatures */
	ret = SUPNP_E_SUCCESS;
	for (int sig_index=0; sig_index<cJSON_GetArraySize(sigs); ++sig_index)
	{
		char * sig_name = cJSON_GetStringValue(cJSON_GetArrayItem(sigs, sig_index));
		if (strcmp(sig_name, SUPNP_DOC_SIG_OWNER) == 0)
		{
			pkey = device_pkey;
		}
		else if (strcmp(sig_name, SUPNP_DOC_SIG_UCA) == 0)
		{
			pkey = uca_pk;
		}
		else
		{
			supnp_error("Unexpected signature name '%s'\n", sig_name);
			ret = SUPNP_E_INVALID_DOCUMENT;
			break;
		}
		/* Extract the hex string signature and convert it to bytes */
		const char * signature = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(supnp_document, sig_name));
		if (verify_signature(sig_name, pkey, signature, (unsigned char *)data, strlen(data)) != OPENSSL_SUCCESS)
		{
			ret = SUPNP_E_INVALID_DOCUMENT;
			break;
		}
		supnp_log("'%s' signature ok.\n", sig_name);
	}
	free(data);
	EVP_PKEY_free(uca_pk);
	EVP_PKEY_free(device_pkey);
	return ret;
}

/* Temporary */
int test_supnp_ducuments()
{
	int ret = SUPNP_E_SUCCESS;

	/* Registration Process example for SD */
	EVP_PKEY * ca_pk = load_public_key_from_pem("../../simulation/CA/public_key.pem");
	X509 * uca_cert  = load_certificate_from_pem("../../simulation/UCA/certificate.pem");
	X509 * sd_cert   = load_certificate_from_pem("../../simulation/SD/certificate.pem");
	X509 * cp_cert   = load_certificate_from_pem("../../simulation/CP/certificate.pem");
	char * dsd = read_file("../../simulation/SD/dsd.json", "r");
	char * sad = read_file("../../simulation/CP/sad.json", "r");
	cJSON* dsd_root = cJSON_Parse(dsd);
	cJSON* sad_root = cJSON_Parse(sad);

	if (verify_supnp_document(dsd_root, ca_pk, uca_cert, sd_cert) == SUPNP_E_SUCCESS)
	{
		supnp_log("DSD OK.\n");
	}
	else
	{
		supnp_error("DSD Verification Failed.\n");
		ret = -1;
	}

	if (verify_supnp_document(sad_root, ca_pk, uca_cert, cp_cert) == SUPNP_E_SUCCESS)
	{
		supnp_log("SAD OK.\n");
	}
	else
	{
		supnp_error("SAD Verification Failed.\n");
		ret = -1;
	}

	/* Free Objects */
	cJSON_Delete(dsd_root);
	cJSON_Delete(sad_root);
	free(sad);
	free(dsd);
	X509_free(cp_cert);
	X509_free(sd_cert);
	X509_free(uca_cert);
	EVP_PKEY_free(ca_pk);

	return ret;
}

/* Temporary */
int test_nonce_encryption()
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	int ret = SUPNP_E_SUCCESS;
	EVP_PKEY * sd_pubkey = NULL;
	EVP_PKEY * sd_prikey = NULL;
	unsigned char * nonce = NULL;
	unsigned char * enc_nonce = NULL;
	unsigned char * dec_nonce = NULL;
	unsigned char * enc_hash = NULL;
	unsigned char * dec_hash = NULL;
	size_t enc_len = 0;
	size_t dec_len = 0;
	size_t ehash_len = 0;
	size_t dhash_len = 0;

	// load keys
	sd_pubkey = load_public_key_from_pem("../../simulation/SD/public_key.pem");
	sd_prikey = load_private_key_from_pem("../../simulation/SD/private_key.pem");

	// RA generates nonce
	nonce = generate_nonce(OPENSSL_CSPRNG_SIZE);
	supnp_log("[*] Generated nonce: ");
	print_as_hex(nonce, OPENSSL_CSPRNG_SIZE);

	// RA encrypts the nonce with participant's public Key
	enc_nonce = encrypt_asym(sd_pubkey, &enc_len, nonce, OPENSSL_CSPRNG_SIZE);
	supnp_log("[*] Encrypted nonce: ");
	print_as_hex(enc_nonce, enc_len);

	// Participant decrypts the challenge with its private key
	dec_nonce = decrypt_asym(sd_prikey, &dec_len, enc_nonce, enc_len);
	supnp_log("[*] Decrypted nonce: ");
	print_as_hex(dec_nonce, dec_len);

	// Participant hash the decrypted n once
	do_sha256(nonce, OPENSSL_CSPRNG_SIZE, hash);
	supnp_log("[*] Hash(nonce): ");
	print_as_hex(hash, SHA256_DIGEST_LENGTH);
	
	// Participant encrypts the nonce hash with its private key
	enc_hash = encrypt_asym(sd_prikey, &ehash_len, hash, SHA256_DIGEST_LENGTH);
	supnp_log("[*] Encrypted Hash(nonce): ");
	print_as_hex(enc_hash, SHA256_DIGEST_LENGTH);

	// RA Decrypts encrypted hash with public key
	dec_hash = decrypt_asym(sd_prikey, &dhash_len, enc_hash, ehash_len);
	supnp_log("[*] Decrypted Hash(nonce): ");
	print_as_hex(dec_hash, SHA256_DIGEST_LENGTH);

	// RA Verifies the hashes are the same
	if ((nonce == NULL) || (enc_nonce == NULL) || (dec_nonce == NULL) || (enc_hash == NULL))
	{
		ret = SUPNP_E_TEST_FAIL;
	}
	else if (memcmp(nonce, dec_nonce, OPENSSL_CSPRNG_SIZE) != 0)
	{
		supnp_error("Decrypted nonce doesn't match the original nonce.\n");
		ret = SUPNP_E_TEST_FAIL;
	}
	else if (memcmp(hash, dec_hash, SHA256_DIGEST_LENGTH) != 0)
	{
		supnp_error("Decrypted nonce hash doesn't match the original hash.\n");
	}
	else
	{
		supnp_log("Public Key verification succeeded.\n");
	}

	freeif(dec_hash);
	freeif(enc_hash);
	freeif(dec_nonce);
	freeif(enc_nonce);
	freeif(nonce);
	EVP_PKEY_free(sd_prikey);
	EVP_PKEY_free(sd_pubkey);
	return ret;
}

/**
 * Test Phase B - registration process
 */
void SUpnp_test_registration()
{
	int ret = 0;

	/**
	 * A participant sends its SAD / DSD, Cert(uca) and Cert(p).
	 * The RA validates the authenticity of the participant's public key & the UCA's public key,
	 * which is included in the certificates, by verifying the signatures of these certificates.
	 *  The RA verifies the authenticity and integrity of the specification document DSD or SAD.
	 * 
	 */
	ret = test_supnp_ducuments();

	/**
	 * The RA needs to verify that the public key really belongs to the participant.
	 * The RA generates a nonce N and encrypts the challenge using the public key of the participant.
	 * The participant decrypts the challenge using its private key. Next,the participant generates a 
	 * signed response to challenge by encrypting the hash of the nonce N (HN = Hash(N)).
	 * The RA decrypts the response using the public key, and checks if the hashes match.
	 */
	ret = test_nonce_encryption();

	/**
	 * todo: verify that the capability of an SD matches its DDD.
	 * The RA retrieves the device description document of the SD. 
	 * The RA matches the services provided by the SD with its HW and SW specification included in the DSD. 
	 * The RA uses an attribute ledger to perform the validation. The ledger maintains a mapping between a 
	 * service type and the HW and SW attributes require to provide the service. 
	 */
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */