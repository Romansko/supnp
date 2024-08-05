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

#include <supnp_captoken.h>
#include <ixml.h>
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


#define supnp_extract_json_string(doc, key, value, label) \
{ \
	value = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(doc, key)); \
	supnp_verify(value, label, "Unexpected '%s'\n", key); \
}

/**
 * Initialize SUPnP secure layer.
 * @return SUPNP_E_SUCCESS on success, SUPNP_E_INTERNAL_ERROR on failure.
 */
int SUpnpInit()
{
    supnp_log("Initializing SUPnP secure layer.\n");
    supnp_verify(init_openssl_wrapper() == OPENSSL_SUCCESS,
        cleanup,
        "Error initializing OpenSSL.\n");
    return SUPNP_E_SUCCESS;
cleanup:
    return SUPNP_E_INTERNAL_ERROR;
}


/**
 * Verify SUPnP document (DSD/ SAD).
 * @param supnp_document a cJSON object representing the SUPnP document
 * @param ca_pkey CA public key
 * @param uca_cert UCA certificate
 * @param device_cert Device certificate
 * @return SUPNP_E_SUCCESS on success, SUPNP_E_INVALID_CERTIFICATE on failure.
 */
int verify_supnp_document(const cJSON *supnp_document,
    EVP_PKEY *ca_pkey,
    X509 *uca_cert,
    X509 *device_cert)
{
    int ret = SUPNP_E_SUCCESS;
    int x, y;
    char *device_name = NULL;
    char *device_type = NULL;
    char *in_doc_pkey = NULL; /* Device public key within the document */
    char *sig_ver_con = NULL; /* Signatures Verification Conditions */
    char *data = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *doc_pk = NULL;
    EVP_PKEY *uca_pk = NULL;
    EVP_PKEY *device_pkey = NULL;

    /* Arguments Verification */
    ret = SUPNP_E_INVALID_ARGUMENT;
    supnp_verify(supnp_document,
        cleanup,
        "Empty DSD / SAD document provided\n");
    supnp_verify(ca_pkey, cleanup, "Empty CA public key provided\n");
    supnp_verify(uca_cert, cleanup, "Empty UCA Certificate provided\n");
    supnp_verify(device_cert, cleanup, "Empty Device Certificate provided\n");

    /* Read SUPnP document name & type */
    ret = SUPNP_E_INVALID_DOCUMENT;
    supnp_extract_json_string(supnp_document,
        SUPNP_DOC_NAME,
        device_name,
        cleanup);
    supnp_extract_json_string(supnp_document,
        SUPNP_DOC_TYPE,
        device_type,
        cleanup);
    supnp_log("Verifying '%s' document. Type: '%s'.\n",
        device_name,
        device_type);

    /* Verify UCA Certificate */
    ret = SUPNP_E_INVALID_CERTIFICATE;
    supnp_verify(
        verify_certificate("UCA", uca_cert, ca_pkey) == OPENSSL_SUCCESS,
        cleanup,
        "Invalid UCA Certificate\n");

    /* Extract UCA Public Key && Verify Device Certificate */
    uca_pk = X509_get_pubkey(uca_cert);
    supnp_verify(
        verify_certificate(device_name, device_cert, uca_pk) == OPENSSL_SUCCESS,
        cleanup,
        "Invalid Device Certificate.\n");

    /* Extract Device Public Key */
    device_pkey = X509_get_pubkey(device_cert);

    /* Verify Device Public Key */
    ret = SUPNP_E_INVALID_DOCUMENT;
    supnp_extract_json_string(supnp_document,
        SUPNP_DOC_PUBLIC_KEY,
        in_doc_pkey,
        cleanup);
    doc_pk = load_public_key_from_hex(in_doc_pkey);
    supnp_verify(doc_pk,
        cleanup,
        "Error loading public key from '%s'.\n",
        SUPNP_DOC_PUBLIC_KEY);
    supnp_verify(EVP_PKEY_eq(doc_pk, device_pkey) == OPENSSL_SUCCESS,
        cleanup,
        "Document's device public key doesn't match Device ceretificate's public key.\n");

    /* Retrieve signature verification conditions */
    supnp_extract_json_string(supnp_document,
        SUPNP_DOC_SIG_CON,
        sig_ver_con,
        cleanup);
    supnp_verify(sscanf(sig_ver_con, "%d-of-%d", &x, &y) == 2,
        cleanup,
        "Error parsing Signature Verification Conditions '%s'.\n",
        SUPNP_DOC_SIG_CON);
    supnp_verify(x >= 0 && y >= 0 && x <= y,
        cleanup,
        "Invalid Signature Verification Conditions '%s'.\n",
        SUPNP_DOC_SIG_CON);
    supnp_log("Signature Verification Conditions: %d-of-%d\n", x, y);

    /* Retrieve Signatures */
    const cJSON *sigs = cJSON_GetObjectItemCaseSensitive(supnp_document,
        SUPNP_DOC_SIGNATURES);
    supnp_verify(cJSON_IsArray(sigs),
        cleanup,
        "Unexpected '%s'\n",
        SUPNP_DOC_SIGNATURES);
    supnp_verify(cJSON_GetArraySize(sigs) == y,
        cleanup,
        "Unexpected number of signatures in '%s'\n",
        SUPNP_DOC_SIGNATURES);
    if (x == 0) {
        ret = SUPNP_E_SUCCESS;
        supnp_log("Signatures verification is not required.\n");
        goto cleanup; /* Done */
    }

    /* Delete signatures from document, leaving only the content. */
    cJSON *doc_content = cJSON_Duplicate(supnp_document, 1);
    cJSON_DeleteItemFromObjectCaseSensitive(doc_content, SUPNP_DOC_SIG_OWNER);
    cJSON_DeleteItemFromObjectCaseSensitive(doc_content, SUPNP_DOC_SIG_UCA);
    data = cJSON_PrintUnformatted(doc_content);

    /* Verify Signatures */
    ret = SUPNP_E_SUCCESS;
    for (int sig_index = 0; sig_index < cJSON_GetArraySize(sigs); ++sig_index) {
        char *sig_name = cJSON_GetStringValue(
            cJSON_GetArrayItem(sigs, sig_index));
        if (strcmp(sig_name, SUPNP_DOC_SIG_OWNER) == 0) {
            pkey = device_pkey;
        } else if (strcmp(sig_name, SUPNP_DOC_SIG_UCA) == 0) {
            pkey = uca_pk;
        } else {
            supnp_error("Unexpected signature name '%s'\n", sig_name);
            ret = SUPNP_E_INVALID_DOCUMENT;
            break;
        }
        /* Extract the hex string signature and convert it to bytes */
        const char *signature = cJSON_GetStringValue(
            cJSON_GetObjectItemCaseSensitive(supnp_document, sig_name));
        if (verify_signature(sig_name,
                pkey,
                signature,
                (unsigned char *)data,
                strlen(data)) != OPENSSL_SUCCESS) {
            ret = SUPNP_E_INVALID_DOCUMENT;
            break;
        }
        supnp_log("'%s' signature ok.\n", sig_name);
    }

    /* Verify Services */
    // todo verify services desc doc vs json

cleanup:
    freeif(data);
    freeif2(doc_pk, EVP_PKEY_free);
    freeif2(uca_pk, EVP_PKEY_free);
    freeif2(device_pkey, EVP_PKEY_free);
    return ret;
}

/* Temporary */
int test_supnp_ducuments(cJSON *dsd, cJSON *sad)
{
    int ret = SUPNP_E_SUCCESS;

    /* Registration Process example for SD */
    EVP_PKEY *ca_pk = load_public_key_from_pem(
        "../../simulation/CA/public_key.pem");
    X509 *uca_cert = load_certificate_from_pem(
        "../../simulation/UCA/certificate.pem");
    X509 *sd_cert = load_certificate_from_pem(
        "../../simulation/SD/certificate.pem");
    X509 *cp_cert = load_certificate_from_pem(
        "../../simulation/CP/certificate.pem");

    if (verify_supnp_document(dsd, ca_pk, uca_cert, sd_cert) ==
        SUPNP_E_SUCCESS) {
        supnp_log("DSD OK.\n");
    } else {
        supnp_error("DSD Verification Failed.\n");
        ret = SUPNP_E_TEST_FAIL;
    }

    if (verify_supnp_document(sad, ca_pk, uca_cert, cp_cert) ==
        SUPNP_E_SUCCESS) {
        supnp_log("SAD OK.\n");
    } else {
        supnp_error("SAD Verification Failed.\n");
        ret = SUPNP_E_TEST_FAIL;
    }

    /* Free Objects */
    freeif2(cp_cert, X509_free);
    freeif2(sd_cert, X509_free);
    freeif2(uca_cert, X509_free);
    freeif2(ca_pk, EVP_PKEY_free);
    return ret;
}

/* Temporary */
int test_nonce_encryption(EVP_PKEY *sd_pk, EVP_PKEY *sd_sk)
{
    int ret = SUPNP_E_SUCCESS;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char *nonce = NULL;
    unsigned char *enc_nonce = NULL;
    unsigned char *dec_nonce = NULL;
    unsigned char *enc_hash = NULL;
    unsigned char *dec_hash = NULL;
    size_t enc_len = 0;
    size_t dec_len = 0;
    size_t ehash_len = 0;
    size_t dhash_len = 0;

    // RA generates nonce
    nonce = generate_nonce(OPENSSL_CSPRNG_SIZE);
    supnp_log("Generated nonce: ");
    print_as_hex(nonce, OPENSSL_CSPRNG_SIZE);

    // RA encrypts the nonce with participant's public Key
    enc_nonce = encrypt_asym(sd_pk, &enc_len, nonce, OPENSSL_CSPRNG_SIZE);
    supnp_log("Encrypted nonce: ");
    print_as_hex(enc_nonce, enc_len);

    // Participant decrypts the challenge with its private key
    dec_nonce = decrypt_asym(sd_sk, &dec_len, enc_nonce, enc_len);
    supnp_log("Decrypted nonce: ");
    print_as_hex(dec_nonce, dec_len);

    // Participant hash the decrypted n once
    ret = do_sha256(hash, nonce, OPENSSL_CSPRNG_SIZE);
    supnp_log("Hash(nonce): ");
    print_as_hex(hash, SHA256_DIGEST_LENGTH);

    // Participant encrypts the nonce hash with its private key
    enc_hash = encrypt_asym(sd_sk, &ehash_len, hash, SHA256_DIGEST_LENGTH);
    supnp_log("Encrypted Hash(nonce): ");
    print_as_hex(enc_hash, SHA256_DIGEST_LENGTH);

    // RA Decrypts encrypted hash with public key
    dec_hash = decrypt_asym(sd_sk, &dhash_len, enc_hash, ehash_len);
    supnp_log("Decrypted Hash(nonce): ");
    print_as_hex(dec_hash, SHA256_DIGEST_LENGTH);

    // RA Verifies the hashes are the same
    if ((nonce == NULL) || (enc_nonce == NULL) || (dec_nonce == NULL) || (
            enc_hash == NULL) || ret == OPENSSL_FAILURE) {
        ret = SUPNP_E_TEST_FAIL;
    } else if (memcmp(nonce, dec_nonce, OPENSSL_CSPRNG_SIZE) != 0) {
        supnp_error("Decrypted nonce doesn't match the original nonce.\n");
        ret = SUPNP_E_TEST_FAIL;
    } else if (memcmp(hash, dec_hash, SHA256_DIGEST_LENGTH) != 0) {
        supnp_error("Decrypted nonce hash doesn't match the original hash.\n");
    } else {
        supnp_log("Public Key verification succeeded.\n");
    }

    freeif(dec_hash);
    freeif(enc_hash);
    freeif(dec_nonce);
    freeif(enc_nonce);
    freeif(nonce);
    return ret;
}

int test_captoken(const device_info_t *info, EVP_PKEY *ra_sk)
{
    int ret = SUPNP_E_TEST_FAIL;
    cJSON *token = NULL;
    supnp_verify(info, cleanup, "NULL device info\n");
    supnp_verify(ra_sk, cleanup, "NULL RA PK\n");
    token = generate_cap_token(info, ra_sk);
    supnp_verify(token, cleanup, "Error generating capability token\n");
    ret = SUPNP_E_SUCCESS;
cleanup:
    freeif2(token, cJSON_Delete);
    return ret;
}

/**
 * Test Phase B - registration process
 */
void SUpnp_test_registration()
{
    int ret = SUPNP_E_TEST_FAIL;
    device_info_t sd_info = {0};
    device_info_t cp_info = {0};
    EVP_PKEY *ra_sk = NULL;
    EVP_PKEY *ra_pk = NULL;
    EVP_PKEY *sd_pk = NULL;
    EVP_PKEY *sd_sk = NULL;
    char *dsd = NULL;
    char *sad = NULL;
    cJSON *dsd_root = NULL;
    cJSON *sad_root = NULL;

    // Load Keys
    ra_pk = load_public_key_from_pem("../../simulation/RA/public_key.pem");
    ra_sk = load_private_key_from_pem("../../simulation/RA/private_key.pem");
    sd_pk = load_public_key_from_pem("../../simulation/SD/public_key.pem");
    sd_sk = load_private_key_from_pem("../../simulation/SD/private_key.pem");

    // Load Documents
    dsd = read_file("../../simulation/SD/dsd.json", "r", NULL);
    sad = read_file("../../simulation/CP/sad.json", "r", NULL);
    dsd_root = cJSON_Parse(dsd);
    sad_root = cJSON_Parse(sad);
    supnp_verify(dsd_root, cleanup, "Error loading DSD document\n");
    supnp_verify(sad_root, cleanup, "Error loading SAD document\n");

    // Fill SD device info
    sd_info.device_type = DEVICE_TYPE_SD;
    sd_info.pk = sd_pk;
    sd_info.desc_doc_uri = "http://192.168.1.100:49152/tvdevicedesc.xml";
    sd_info.cap_token_uri = "http://192.168.1.100:49152/captoken.json";
    sd_info.desc_doc = ixmlLoadDocument("./web/tvdevicedesc.xml");
    supnp_verify(sd_info.desc_doc, cleanup, "Error loading device description document\n");

    // Fill CP device info
    cp_info.device_type = DEVICE_TYPE_CP;
    cp_info.pk = sd_pk;
    cp_info.desc_doc_uri = ""; /* Not applicable */
    cp_info.cap_token_uri = "http://192.168.1.100:49152/captoken.json";
    cp_info.desc_doc = ixmlLoadDocument("./web/tvcontrolSCPD.xml");
    supnp_verify(cp_info.desc_doc, cleanup, "Error loading device description document\n");

    /**
     * A participant sends its SAD / DSD, Cert(uca) and Cert(p).
     * The RA validates the authenticity of the participant's public key & the UCA's public key,
     * which is included in the certificates, by verifying the signatures of these certificates.
     * The RA verifies the authenticity and integrity of the specification document DSD or SAD.
     */
    ret = test_supnp_ducuments(dsd_root, sad_root);
    supnp_log("test_supnp_ducuments: %d\n", ret);

    /**
     * The RA needs to verify that the public key really belongs to the participant.
     * The RA generates a nonce N and encrypts the challenge using the public key of the participant.
     * The participant decrypts the challenge using its private key. Next,the participant generates a
     * signed response to challenge by encrypting the hash of the nonce N (HN = Hash(N)).
     * The RA decrypts the response using the public key, and checks if the hashes match.
     */
    ret = test_nonce_encryption(sd_pk, sd_sk);
    supnp_log("test_nonce_encryption: %d\n", ret);

    /**
     * todo: verify that the capability of an SD matches its DDD.
     * The RA retrieves the device description document of the SD.
     * The RA matches the services provided by the SD with its HW and SW specification included in the DSD.
     * The RA uses an attribute ledger to perform the validation. The ledger maintains a mapping between a
     * service type and the HW and SW attributes require to provide the service.
     */

    /* Cap Token */
    ret = test_captoken(&sd_info, ra_sk);
    supnp_log("test sd captoken: %d\n", ret);
    ret = test_captoken(&cp_info, ra_sk);
    supnp_log("test sd captoken: %d\n", ret);

cleanup:
    freeif2(ra_sk, EVP_PKEY_free);
    freeif2(ra_pk, EVP_PKEY_free);
    freeif2(sd_sk, EVP_PKEY_free);
    freeif2(sd_pk, EVP_PKEY_free);
    freeif(dsd);
    freeif(sad);
    freeif2(dsd_root, cJSON_Delete);
    freeif2(sad_root, cJSON_Delete);
    freeif2(sd_info.desc_doc, ixmlDocument_free);

}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */