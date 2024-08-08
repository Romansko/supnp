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

#include "file_utils.h"
#include "openssl_wrapper.h"
#include "supnp.h"
#include "supnp_captoken.h"
#include "supnp_device.h"
#include "supnp_err.h"
#include <cJSON/cJSON.h>
#include <ixml.h>

// todo: refactor to openssl_wrapper
#include <openssl/x509.h>
//

#ifdef __cplusplus
extern "C" {
#endif

/* Description Document related */
static const char* SERVICE = "service";
static const char* SERVICE_ID = "serviceId";
static const char* SERVICE_TYPE = "serviceType";
static const char* SERVICE_LIST = "serviceList";


/* https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf#page=52 */
static const char* SERVICE_ID_FORMAT = "urn:upnp-org:serviceId:%s";
static const char* SERVICE_TYPE_FORMAT = "urn:schemas-upnp-org:service:%[^:]:%d";

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
    supnp_verify(init_openssl_wrapper() == OPENSSL_SUCCESS, cleanup, "Error initializing OpenSSL.\n");
    return SUPNP_E_SUCCESS;
cleanup:
    return SUPNP_E_INTERNAL_ERROR;
}

/**
 * Retrieve the service list from a device description document
 * Implemented in SampleUtil_GetFirstServiceList, sample_util.c
 * sample_util.c is not a library file, hence the function is copied.
 * @param doc device description document
 * @return list of services on success, NULL on failure
 * @note The caller is responsible for freeing the returned list.
 * (ixmlNodeList_free)
 */
IXML_NodeList* get_xml_service_list(IXML_Document* doc)
{
    IXML_NodeList* ServiceList = NULL;
    IXML_NodeList* servlistnodelist = NULL;
    IXML_Node* servlistnode = NULL;

    servlistnodelist = ixmlDocument_getElementsByTagName(doc, SERVICE_LIST);
    if (servlistnodelist && ixmlNodeList_length(servlistnodelist))
    {
        /* we only care about the first service list, from the root device */
        servlistnode = ixmlNodeList_item(servlistnodelist, 0);
        /* create as list of DOM nodes */
        ServiceList = ixmlElement_getElementsByTagName((IXML_Element*)servlistnode, "service");
    }
    freeif2(servlistnodelist, ixmlNodeList_free);
    return ServiceList;
}

/**
 * Verify SUPnP document (DSD/ SAD).
 * @param ca_pkey CA public key
 * @param uca_cert UCA certificate
 * @param dev Device info
 * @return SUPNP_E_SUCCESS on success, SUPNP_E_INVALID_CERTIFICATE on failure.
 */
int verify_supnp_document(EVP_PKEY* ca_pkey, X509* uca_cert, const supnp_device_t* dev)
{
    int ret = SUPNP_E_INVALID_ARGUMENT;
    int x, y;
    char* dev_name = NULL;
    char* dev_type = NULL;
    char* in_doc_pkey = NULL; /* Device public key within the document */
    char* sig_ver_con = NULL; /* Signatures Verification Conditions */
    char* data = NULL;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY* doc_pk = NULL;
    EVP_PKEY* uca_pk = NULL;
    EVP_PKEY* device_pkey = NULL;
    IXML_NodeList* xml_services = NULL;

    /* Arguments Verification */
    supnp_verify(ca_pkey, cleanup, "Empty CA public key provided\n");
    supnp_verify(uca_cert, cleanup, "Empty UCA Certificate provided\n");
    supnp_verify(supnp_verify_device(dev) == SUPNP_DEV_OK, cleanup, "Invalid device\n");

    /* Read SUPnP document name & type */
    ret = SUPNP_E_INVALID_DOCUMENT;
    supnp_extract_json_string(dev->supnp_doc, SUPNP_DOC_NAME, dev_name, cleanup);
    supnp_extract_json_string(dev->supnp_doc, SUPNP_DOC_TYPE, dev_type, cleanup);
    supnp_log("Verifying '%s' document. Type: '%s'.\n", dev_name, dev_type);

    /* Verify UCA Certificate */
    ret = SUPNP_E_INVALID_CERTIFICATE;
    supnp_verify(verify_certificate("UCA", uca_cert, ca_pkey) == OPENSSL_SUCCESS, cleanup, "Invalid UCA cert.\n");

    /* Extract UCA Public Key && Verify Device Certificate */
    uca_pk = X509_get_pubkey(uca_cert);
    supnp_verify(verify_certificate(dev_name, dev->cert, uca_pk) == OPENSSL_SUCCESS, cleanup, "Invalid Device cert.\n");

    /* Extract Device Public Key */
    device_pkey = X509_get_pubkey(dev->cert);

    /* Verify Device Public Key */
    ret = SUPNP_E_INVALID_DOCUMENT;
    supnp_extract_json_string(dev->supnp_doc, SUPNP_DOC_PUBLIC_KEY, in_doc_pkey, cleanup);
    doc_pk = load_public_key_from_hex(in_doc_pkey);
    supnp_verify(doc_pk, cleanup, "Error loading public key from '%s'.\n", SUPNP_DOC_PUBLIC_KEY);
    supnp_verify(EVP_PKEY_eq(doc_pk, device_pkey) == OPENSSL_SUCCESS, cleanup,
                 "Document's device public key doesn't match Device ceretificate's public key.\n");

    /**
     * Verify Services.
     * The RA retrieves the device description document of the SD.
     * The RA matches the services provided by the SD with its HW and SW specification included in the DSD.
     * The RA uses an attribute ledger to perform the validation.
     * The ledger maintains a mapping between a service type and the HW and SW attributes require to provide the service.
     * todo: verify that the capability of an SD matches its DDD. Maintain Ledger.
     */
    const cJSON* json_services = cJSON_GetObjectItemCaseSensitive(dev->supnp_doc, SUPNP_DOC_SERVICES);
    xml_services = get_xml_service_list(dev->desc_doc);
    supnp_verify(json_services, cleanup, "Couldn't find services tagname '%s' in SUPnP Document.\n",
                 SUPNP_DOC_SERVICES);
    supnp_verify(xml_services, cleanup, "Couldn't find services tagname '%s' in device description document.\n",
                 SERVICE_LIST);
    const int json_services_number = cJSON_GetArraySize(json_services);
    const int xml_services_number = ixmlNodeList_length(xml_services);
    supnp_verify(json_services_number == xml_services_number, cleanup,
                 "Number of services in SUPnP Document (%d) doesn't match the number of services in description document (%d).\n",
                 json_services_number, xml_services_number);

    for (int i = 0; i < xml_services_number; ++i)
    {
        ret = SUPNP_E_INVALID_DOCUMENT;
        IXML_Node* service = ixmlNodeList_item(xml_services, i);
        IXML_NodeList* service_nodes = ixmlNode_getChildNodes(service);
        supnp_verify((service_nodes) && (ixmlNodeList_length(service_nodes) > 0), loop_cleanup,
                     "Couldn't find child nodes in service node.\n");
        char* _service_id = NULL;
        char* _service_type = NULL;
        for (size_t j = 0; j < ixmlNodeList_length(service_nodes); ++j)
        {
            IXML_Node* node = ixmlNodeList_item(service_nodes, j);
            if (node == NULL)
            {
                continue;
            }
            const char* val = ixmlNode_getNodeValue(node->firstChild);
            if (strcmp(ixmlNode_getNodeName(node), SERVICE_ID) == 0)
            {
                _service_id = malloc(strlen(val) + 1);
                supnp_verify(sscanf(val, SERVICE_ID_FORMAT, _service_id) == 1, loop_cleanup,
                             "Couldn't parse service id\n");
            }
            else if (strcmp(ixmlNode_getNodeName(node), SERVICE_TYPE) == 0)
            {
                int ver;
                _service_type = malloc(strlen(val) + 1);
                supnp_verify(sscanf(val, SERVICE_TYPE_FORMAT, _service_type, &ver) == 2, loop_cleanup,
                             "Couldn't parse service type\n");
            }
        }
        supnp_verify((_service_id) && (_service_type), loop_cleanup,
                     "Couldn't find tagname '%s' or '%s' in service node.\n", SERVICE_ID, SERVICE_TYPE);
        cJSON* _json_service = cJSON_GetObjectItemCaseSensitive(json_services, _service_id);
        supnp_verify(_json_service, loop_cleanup, "Couldn't find service id '%s' in SUPnP Document.\n", _service_id);
        supnp_verify(strcmp(_json_service->valuestring, _service_type) == 0, loop_cleanup,
                     "Unexpected service type for service id '%s': '%s' vs '%s'\n", _service_id,
                     _json_service->valuestring, _service_type);
        ret = SUPNP_E_SUCCESS;

    loop_cleanup:
        freeif(_service_id);
        freeif(_service_type);
        freeif2(service_nodes, ixmlNodeList_free);
        if (ret == SUPNP_E_INVALID_DOCUMENT)
            break;
    }
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup, "Services verification failed.\n");

    /* Retrieve signature verification conditions */
    supnp_extract_json_string(dev->supnp_doc, SUPNP_DOC_SIG_CON, sig_ver_con, cleanup);
    supnp_verify(sscanf(sig_ver_con, "%d-of-%d", &x, &y) == 2, cleanup,
                 "Error parsing Signature Verification Conditions '%s'.\n", SUPNP_DOC_SIG_CON);
    supnp_verify(x >= 0 && y >= 0 && x <= y, cleanup, "Invalid Signature Verification Conditions '%s'.\n",
                 SUPNP_DOC_SIG_CON);
    supnp_log("Signature Verification Conditions: %d-of-%d\n", x, y);

    /* Retrieve Signatures */
    const cJSON* sigs = cJSON_GetObjectItemCaseSensitive(dev->supnp_doc, SUPNP_DOC_SIGNATURES);
    supnp_verify(cJSON_IsArray(sigs), cleanup, "Unexpected '%s'\n", SUPNP_DOC_SIGNATURES);
    supnp_verify(cJSON_GetArraySize(sigs) == y, cleanup,
                 "Unexpected number of signatures in '%s'\n", SUPNP_DOC_SIGNATURES);
    if (x == 0)
    {
        ret = SUPNP_E_SUCCESS;
        supnp_log("Signatures verification is not required.\n");
        goto cleanup; /* Done */
    }

    /* Delete signatures from document, leaving only the content. */
    cJSON* doc_content = cJSON_Duplicate(dev->supnp_doc, 1);
    cJSON_DeleteItemFromObjectCaseSensitive(doc_content, SUPNP_DOC_SIG_OWNER);
    cJSON_DeleteItemFromObjectCaseSensitive(doc_content, SUPNP_DOC_SIG_UCA);
    data = cJSON_PrintUnformatted(doc_content);

    /* Verify Signatures */
    for (int sig_index = 0; sig_index < cJSON_GetArraySize(sigs); ++sig_index)
    {
        char* sig_name = cJSON_GetStringValue(cJSON_GetArrayItem(sigs, sig_index));
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
        const char* signature = cJSON_GetStringValue(
            cJSON_GetObjectItemCaseSensitive(dev->supnp_doc, sig_name));
        if (verify_signature(sig_name, pkey, signature, (unsigned char*)data, strlen(data)) != OPENSSL_SUCCESS)
        {
            ret = SUPNP_E_INVALID_DOCUMENT;
            break;
        }
        supnp_log("'%s' signature ok.\n", sig_name);
    }
    ret = SUPNP_E_SUCCESS;

cleanup:
    freeif(data);
    freeif2(doc_pk, EVP_PKEY_free);
    freeif2(uca_pk, EVP_PKEY_free);
    freeif2(device_pkey, EVP_PKEY_free);
    freeif2(xml_services, ixmlNodeList_free);
    return ret;
}

/**
 * nonce challenge tests in order to validate that a public key really belongs to the participant.
 * @param pk public key
 * @param sk private key
 */
void test_nonce_encryption(EVP_PKEY* pk, EVP_PKEY* sk)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char* nonce = NULL;
    unsigned char* enc_nonce = NULL;
    unsigned char* dec_nonce = NULL;
    unsigned char* enc_hash = NULL;
    unsigned char* dec_hash = NULL;
    size_t enc_len = 0;
    size_t dec_len = 0;
    size_t ehash_len = 0;
    size_t dhash_len = 0;
    supnp_verify(pk && sk, cleanup, "NULL keys\n");

    /* Generates a nonce  */
    nonce = generate_nonce(OPENSSL_CSPRNG_SIZE);
    supnp_verify(nonce, cleanup, "Error generating nonce.\n");
    //supnp_log("Generated nonce: ");    // todo upnp_log DEBUG
    //print_as_hex(nonce, OPENSSL_CSPRNG_SIZE);

    /* Encrypt the challenge using the participant's public key */
    enc_nonce = encrypt_asym(pk, &enc_len, nonce, OPENSSL_CSPRNG_SIZE);
    supnp_verify(enc_nonce, cleanup, "Error encrypting nonce.\n");
    //supnp_log("Encrypted nonce: ");    // todo upnp_log DEBUG
    //print_as_hex(enc_nonce, enc_len);

    /* Decrypt the challenge using the participant's private key */
    dec_nonce = decrypt_asym(sk, &dec_len, enc_nonce, enc_len);
    supnp_verify(dec_nonce, cleanup, "Error decrypting nonce.\n");
    //supnp_log("Decrypted nonce: ");    // todo upnp_log DEBUG
    //print_as_hex(dec_nonce, dec_len);

    /* hash the nonce N (HN = Hash(N)). */
    supnp_verify(do_sha256(hash, nonce, OPENSSL_CSPRNG_SIZE) == OPENSSL_SUCCESS, cleanup, "Error hashing nonce.\n");
    //supnp_log("Hash(nonce): ");    // todo upnp_log DEBUG
    //print_as_hex(hash, SHA256_DIGEST_LENGTH);

    /* Encrypt the nonce hash with participant's private key (signed response) */
    enc_hash = encrypt_asym(sk, &ehash_len, hash, SHA256_DIGEST_LENGTH);
    supnp_verify(enc_hash, cleanup, "Error encrypting hash(nonce).\n");
    //supnp_log("Encrypted Hash(nonce): ");    // todo upnp_log DEBUG
    //print_as_hex(enc_hash, SHA256_DIGEST_LENGTH);

    /* Decrypt the response using the public key */
    dec_hash = decrypt_asym(sk, &dhash_len, enc_hash, ehash_len);
    supnp_verify(dec_hash, cleanup, "Error decrypting hash(nonce).\n");
    //supnp_log("Decrypted Hash(nonce): ");    // todo upnp_log DEBUG
    //print_as_hex(dec_hash, SHA256_DIGEST_LENGTH);

    /* Verify hashes matches */
    supnp_verify(memcmp(nonce, dec_nonce, OPENSSL_CSPRNG_SIZE) == 0, cleanup,
        "Decrypted nonce doesn't match the original nonce.\n");
    supnp_verify(memcmp(hash, dec_hash, SHA256_DIGEST_LENGTH) == 0, cleanup,
        "Decrypted nonce hash doesn't match the original hash.\n");
    supnp_log("nonce encryption test ok.\n");

cleanup:
    freeif(dec_hash);
    freeif(enc_hash);
    freeif(dec_nonce);
    freeif(enc_nonce);
    freeif(nonce);
}

void test_captoken_generation(const supnp_device_t* dev, EVP_PKEY* ra_sk)
{
    cJSON* token = NULL;
    supnp_verify(supnp_verify_device(dev), cleanup, "Device verification failed\n");
    supnp_verify(ra_sk, cleanup, "NULL RA PK\n");
    token = generate_cap_token(dev, ra_sk);
    supnp_verify(token, cleanup, "Error generating %s's capability token\n", supnp_device_type_str(dev->type));
    supnp_log("%s's Capability Token: %s\n", supnp_device_type_str(dev->type), cJSON_Print(token));
cleanup:
    freeif2(token, cJSON_Delete);
}

/**
 * Test Phase B - registration process
 */
void SUpnp_test_registration()
{
    supnp_device_t sd_info = {0};
    supnp_device_t cp_info = {0};
    EVP_PKEY* ca_pk = NULL;
    X509* uca_cert = NULL;
    EVP_PKEY* ra_sk = NULL;
    EVP_PKEY* ra_pk = NULL;
    char* dsd = NULL;
    char* sad = NULL;

    /* Load UCA Certificate & CA's public key */
    ca_pk = load_public_key_from_pem("../../simulation/CA/public_key.pem");
    uca_cert = load_certificate_from_pem("../../simulation/UCA/certificate.pem");

    /* Load RA Keys */
    ra_pk = load_public_key_from_pem("../../simulation/RA/public_key.pem");
    ra_sk = load_private_key_from_pem("../../simulation/RA/private_key.pem");

    /* Read SUPnP Documents */
    dsd = read_file("../../simulation/SD/dsd.json", "r", NULL);
    sad = read_file("../../simulation/CP/sad.json", "r", NULL);

    /* Load SD device info */
    sd_info.type = DEVICE_TYPE_SD;
    sd_info.pk = load_public_key_from_pem("../../simulation/SD/public_key.pem");
    sd_info.sk = load_private_key_from_pem("../../simulation/SD/private_key.pem");
    sd_info.cert = load_certificate_from_pem("../../simulation/SD/certificate.pem");
    sd_info.desc_doc_uri = strdup("http://192.168.1.100:49152/tvdevicedesc.xml");
    sd_info.cap_token_uri = strdup("http://192.168.1.100:49152/captoken.json");
    sd_info.desc_doc = ixmlLoadDocument("./web/tvdevicedesc.xml");
    sd_info.supnp_doc = cJSON_Parse(dsd);

    /* Load CP device info */
    cp_info.type = DEVICE_TYPE_CP;
    cp_info.pk = load_public_key_from_pem("../../simulation/CP/public_key.pem");
    cp_info.sk = load_private_key_from_pem("../../simulation/CP/private_key.pem");
    cp_info.cert = load_certificate_from_pem("../../simulation/CP/certificate.pem");
    cp_info.desc_doc_uri = strdup(""); /* Not applicable */
    cp_info.cap_token_uri = strdup("http://192.168.1.100:49152/captoken.json");
    cp_info.desc_doc = ixmlLoadDocument("./web/tvcontrolSCPD.xml");
    cp_info.supnp_doc = cJSON_Parse(sad);

    /**
     * A participant sends its SAD / DSD, Cert(uca) and Cert(p).
     * The RA validates the authenticity of the participant's public key & the UCA's public key,
     * which is included in the certificates, by verifying the signatures of these certificates.
     * The RA verifies the authenticity and integrity of the specification document DSD or SAD.
     */
    if (verify_supnp_document(ca_pk, uca_cert, &sd_info) == SUPNP_E_SUCCESS)
    {
        supnp_log("Device Specification Document (DSD) for SD OK.\n");
    }
    if (verify_supnp_document(ca_pk, uca_cert, &cp_info) == SUPNP_E_SUCCESS)
    {
        supnp_log("Service Action Document (SAD) for CP OK.\n");
    }

    /* Nonce Challenge Tests */
    test_nonce_encryption(sd_info.pk, sd_info.sk);

    /* Cap Token Generation Tests */
    test_captoken_generation(&sd_info, ra_sk);
    test_captoken_generation(&cp_info, ra_sk);

cleanup:
    freeif2(uca_cert, X509_free);
    freeif2(ca_pk, EVP_PKEY_free);
    freeif2(ra_sk, EVP_PKEY_free);
    freeif2(ra_pk, EVP_PKEY_free);
    supnp_free_device_content(&sd_info);
    supnp_free_device_content(&cp_info);
    freeif(dsd);
    freeif(sad);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */
