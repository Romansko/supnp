/*!
 * \addtogroup SUPnP
 *
 * \file supnp_captoken.c
 *
 * \brief source file for SUPnP CapToken algorithms. Implementing logics from
 * the paper "Kayas, G., Hossain, M., Payton, J., & Islam, S. R. (2021). SUPnP:
 * Secure Access and Service Registration for UPnP-Enabled Internet of Things.
 * IEEE Internet of Things Journal, 8(14), 11561-11580."
 *
 * \author Roman Koifman
 */
#include "supnp_captoken.h"
#include "supnp_err.h"
#include "supnp_device.h"
#include "openssl_wrapper.h"
#include <cJSON/cJSON.h>
#include <ixml.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef ENABLE_SUPNP

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Copy src to dst and increment dst by size
 * @param dst destination buffer
 * @param src source buffer
 * @param size size of source buffer
 */
#define copy_inc(dst, src, size) \
    { \
        memcpy(dst, src, size); \
        dst += size; \
    }

/**
 * Helper function to convert string to cJSON.
 * @note the function free the input string.
 * @param string input string
 * @return cJSON object on success, NULL on failure
 */
cJSON* string_to_json_string(char* string)
{
    cJSON* node = NULL;
    supnp_verify(string != NULL, cleanup, "NULL string\n");
    node = cJSON_CreateString(string);
cleanup:
    freeif(string);
    return node;
}

/**
 * Helper function to convert bytes to cJSON.
 * @note the function free the input bytes.
 * @param bytes input bytes
 * @return cJSON object on success, NULL on failure
 */
cJSON* bytes_to_json_string(unsigned char* bytes)
{
    cJSON* node = NULL;
    supnp_verify(bytes != NULL, cleanup, "NULL bytes\n");
    char* hex_string = binary_to_hex_string(bytes, ID_SIZE);
    node = cJSON_CreateString(hex_string);
cleanup:
    freeif(hex_string);
    freeif(bytes);
    return node;
}

cJSON* get_timestamp()
{
    time_t rawtime;
    time(&rawtime);
    const struct tm* timeinfo = localtime(&rawtime);
    return cJSON_CreateString(asctime(timeinfo));
}

/**
 * Generate a CapToken for a Service Device which consists of:
 *   ID - Random Token ID
 *   ISSUER_INSTANT - Current time
 *   RA_PK - RA Public Key
 *   SD_PK - SD Public Key
 *   RA_SIG - RA Signature on Cap Token's content
 *   TYPE - "SERVICE-DEVICE"
 *   ADV_SIG - RA Signature on (description uri || cap token uri).
 *   SERVICES - List of service types and corresponding signature by RA on thier
 * ID. Note: This differs from the paper, where the signature is on the
 * description.
 *
 * @param dev device information
 * @param sk_ra RA private key
 * @return CapToken on success, NULL on failure
 */
cJSON* generate_cap_token(const supnp_device_t* dev, EVP_PKEY* sk_ra)
{
    cJSON* cap_token = NULL;
    char* desc_doc = NULL;
    char* concatenate_uri = NULL; // description uri || token uri
    char* cap_token_content = NULL;

    /* Params verification */
    supnp_verify(supnp_verify_device(dev) == SUPNP_DEV_OK, error, "Device verification error\n");

    /* Init Cap Token */
    cap_token = cJSON_CreateObject();
    supnp_verify(cap_token, error, "cap_token initial generation failed\n");

    /* ID */
    cJSON* id = bytes_to_json_string(generate_nonce(ID_SIZE));
    supnp_verify(id, error, "ID Generation failed\n");
    cJSON_AddItemToObject(cap_token, "ID", id);

    /* Timestamp */
    cJSON* _timestamp = get_timestamp();
    supnp_verify(_timestamp, error, "Timestamp Generation failed\n");
    cJSON_AddItemToObject(cap_token, CT_TIMESTAMP, _timestamp);

    /* Export RA Public Key */
    cJSON* _pk_ra = bytes_to_json_string(public_key_to_bytes(sk_ra, NULL));
    supnp_verify(_pk_ra, error, "RA Public Key exporting failed\n");
    cJSON_AddItemToObject(cap_token, RA_PK, _pk_ra);

    /* Export Device Public Key & Type */
    cJSON* _pk_dev = bytes_to_json_string(public_key_to_bytes(dev->pk, NULL));
    supnp_verify(_pk_dev, error, "Device Public Key exporting failed\n");
    switch (dev->type)
    {
    case DEVICE_TYPE_SD:
        cJSON_AddItemToObject(cap_token, SD_PK, _pk_dev);
        cJSON_AddItemToObject(cap_token, CT_TYPE, cJSON_CreateString(SD_TYPE_STR));
        break;
    case DEVICE_TYPE_CP:
        cJSON_AddItemToObject(cap_token, CP_PK, _pk_dev);
        cJSON_AddItemToObject(cap_token, CT_TYPE, cJSON_CreateString(CP_TYPE_STR));
        break;
    }

    /* Sign advertisement URI (description uri || token uri) */
    if (dev->type == DEVICE_TYPE_SD)
    {
        concatenate_uri = malloc(strlen(dev->desc_doc_uri) + strlen(dev->cap_token_uri) + 1);
        supnp_verify(concatenate_uri, error, "concatenate_uri memory allocation failed\n");
        strcpy(concatenate_uri, dev->desc_doc_uri);
        strcat(concatenate_uri, dev->cap_token_uri);
        cJSON* _adv_sig = bytes_to_json_string(sign(sk_ra, (const unsigned char*)concatenate_uri,
                                                    strlen(concatenate_uri)));
        supnp_verify(_adv_sig, error, "Advertisement Signature exporting failed\n");
        cJSON_AddItemToObject(cap_token, CT_ADV_SIG, _adv_sig);
    }

    /* Sign Cap Token URI */
    if (dev->type == DEVICE_TYPE_CP)
    {
        cJSON* _uri_sig = bytes_to_json_string(sign(sk_ra, (const unsigned char*)dev->cap_token_uri,
                                                    strlen(dev->cap_token_uri)));
        supnp_verify(_uri_sig, error, "Advertisement Signature exporting failed\n");
        cJSON_AddItemToObject(cap_token, CT_URI_SIG, _uri_sig);
    }

    /* Sign Device Description Document */
    if (dev->type == DEVICE_TYPE_SD)
    {
        desc_doc = ixmlDocumenttoString(dev->desc_doc);
        const size_t doc_size = strlen(desc_doc);
        supnp_verify(desc_doc, error, "ixmlPrintDocument failed\n");
        cJSON* _doc_sig = bytes_to_json_string(sign(sk_ra, (unsigned char*)desc_doc, doc_size));
        supnp_verify(_doc_sig, error, "Description Signature exporting failed\n");
        cJSON_AddItemToObject(cap_token, CT_DESC_SIG, _doc_sig);
    }

    /**
     * For each service in service_list do
     *   service_sig = sign(sk_pk, hash(service_id));
     *   capt_token.add_Service(service_sig, service_type);
     */
    // services for cap token generation.
    const cJSON* service_list = cJSON_GetObjectItemCaseSensitive(dev->supnp_doc, "SERVICES");
    supnp_verify(service_list, cleanup, "Couldn't find services tagname in SUPnP Document.\n");
    cJSON* _services = cJSON_CreateObject();
    supnp_verify(_services, error, "Couldn't create services array\n");
    cJSON_AddItemToObject(cap_token, CT_SERVICES, _services);
    const cJSON* p_service = service_list->child;
    while (p_service != NULL)
    {
        const char* _id = p_service->string;
        const char* _type = p_service->valuestring;
        if (_id && _type)
        {
            cJSON* _service_sig = bytes_to_json_string(sign(sk_ra, (unsigned char*)_id, strlen(_id)));
            cJSON_AddItemToObject(_services, _type, _service_sig);
        }
        p_service = p_service->next;
    }

    /* Sign the cap token's content */
    cap_token_content = cJSON_PrintUnformatted(cap_token);
    cJSON* _content_sig = bytes_to_json_string(sign(sk_ra, (unsigned char*)cap_token_content,
                                                    strlen(cap_token_content)));
    supnp_verify(_content_sig, error, "Signing Cap Token content failed\n");
    cJSON_AddItemToObject(cap_token, RA_SIG, _content_sig);

    goto cleanup;

error:
    freeif2(cap_token, cJSON_Delete);

cleanup:
    freeif(cap_token_content);
    freeif(desc_doc);
    freeif(concatenate_uri);
    return cap_token;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */
