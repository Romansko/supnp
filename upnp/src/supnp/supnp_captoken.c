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
#include "openssl_wrapper.h"

#include <ixml.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cJSON/cJSON.h>

#ifdef ENABLE_SUPNP

/* Description Document related */
#define SERVICE      "service"
#define SERVICE_ID   "serviceId"
#define SERVICE_TYPE "serviceType"
#define SERVICE_LIST "serviceList"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Copy src to dst and increment dst by size
 * @param dst destination buffer
 * @param src source buffer
 * @param size size of source buffer
 */
#define copy_inc(dst, src, size) { \
    memcpy(dst, src, size); \
    dst += size; \
}

/**
 * Helper function to convert string to cJSON.
 * @note the function free the input string.
 * @param string input string
 * @return cJSON object on success, NULL on failure
 */
cJSON *json_string(char *string)
{
    cJSON *node = NULL;
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
cJSON *bytes_to_json_string(unsigned char *bytes)
{
    cJSON *node = NULL;
    supnp_verify(bytes != NULL, cleanup, "NULL bytes\n");
    char *hex_string = binary_to_hex_string(bytes, ID_SIZE);
    node = cJSON_CreateString(hex_string);
cleanup:
    freeif(hex_string);
    freeif(bytes);
    return node;
}

cJSON *get_timestamp()
{
    time_t rawtime;
    time(&rawtime);
    const struct tm *timeinfo = localtime(&rawtime);
    return cJSON_CreateString(asctime(timeinfo));
}

/**
 * Retrieve the service list from a device description document
 * Implemented in SampleUtil_GetFirstServiceList, sample_util.c
 * sample_util.c is not a library file, hence the function is copied.
 * @param doc device description document
 * @return list of services on success, NULL on failure
 * @note Caller is responsible for ixmlNodeList_free the returned list
 */
IXML_NodeList *get_service_list(IXML_Document *doc)
{
    IXML_NodeList *ServiceList = NULL;
    IXML_NodeList *servlistnodelist = NULL;
    IXML_Node *servlistnode = NULL;

    servlistnodelist = ixmlDocument_getElementsByTagName(doc, SERVICE_LIST);
    if (servlistnodelist && ixmlNodeList_length(servlistnodelist)) {
        /* we only care about the first service list, from the root device */
        servlistnode = ixmlNodeList_item(servlistnodelist, 0);
        /* create as list of DOM nodes */
        ServiceList = ixmlElement_getElementsByTagName(
            (IXML_Element *)servlistnode,
            "service");
    }
    freeif2(servlistnodelist, ixmlNodeList_free);

    return ServiceList;
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
 *   SERVICES - List of service types and corresponding signature by RA on thier ID.
 *              Note: This differs from the paper, where the signature is on the description.
 *
 * @param info device information
 * @param sk_ra RA private key
 * @return CapToken on success, NULL on failure
 */
cJSON *generate_cap_token(const device_info_t *info, EVP_PKEY *sk_ra)
{
    // todo verify device_info
    int ret = SUPNP_E_INTERNAL_ERROR;
    cJSON *cap_token = NULL;
    char *desc_doc = NULL;
    char *concatenate_uri = NULL; // description uri || token uri
    char *cap_token_content = NULL;
    IXML_NodeList *service_list = NULL;

    supnp_verify(info, error, "NULL sd_info\n");
    supnp_verify(sk_ra, error, "NULL ra_pkey\n");

    /* Init Cap Token */
    cap_token = cJSON_CreateObject();
    supnp_verify(cap_token, error, "cap_token initial generation failed\n");

    /* ID */
    cJSON *id = bytes_to_json_string(generate_nonce(ID_SIZE));
    supnp_verify(id, error, "ID Generation failed\n");
    cJSON_AddItemToObject(cap_token, "ID", id);

    /* Timestamp */
    cJSON *_timestamp = get_timestamp();
    supnp_verify(_timestamp, error, "Timestamp Generation failed\n");
    cJSON_AddItemToObject(cap_token, CT_TIMESTAMP, _timestamp);

    /* Export RA Public Key */
    cJSON *_pk_ra = bytes_to_json_string(public_key_to_bytes(sk_ra, NULL));
    supnp_verify(_pk_ra, error, "RA Public Key exporting failed\n");
    cJSON_AddItemToObject(cap_token, RA_PK, _pk_ra);

    /* Export Device Public Key */
    cJSON *_pk_dev = bytes_to_json_string(public_key_to_bytes(info->pk, NULL));
    supnp_verify(_pk_dev, error, "Device Public Key exporting failed\n");

    if (info->device_type == DEVICE_TYPE_SD) {
        cJSON_AddItemToObject(cap_token, SD_PK, _pk_dev);
    } else if (info->device_type == DEVICE_TYPE_CP) {
        cJSON_AddItemToObject(cap_token, CP_PK, _pk_dev);
    }

    /* Sign advertisement URI (description uri || token uri) */
    if (info->device_type == DEVICE_TYPE_SD) {
        concatenate_uri = malloc(strlen(info->desc_doc_uri) +
                                 strlen(info->cap_token_uri) + 1);
        supnp_verify(concatenate_uri,
            error,
            "concatenate_uri memory allocation failed\n");
        strcpy(concatenate_uri, info->desc_doc_uri);
        strcat(concatenate_uri, info->cap_token_uri);
        cJSON *_adv_sig = bytes_to_json_string(sign(sk_ra,
            (const unsigned char *)concatenate_uri,
            strlen(concatenate_uri)));
        supnp_verify(_adv_sig,
            error,
            "Advertisement Signature exporting failed\n");
        cJSON_AddItemToObject(cap_token, CT_ADV_SIG, _adv_sig);
    }

    /* Sign Device Description Document */
    if (info->device_type == DEVICE_TYPE_SD) {
        desc_doc = ixmlDocumenttoString(info->desc_doc);
        const size_t doc_size = strlen(desc_doc);
        supnp_verify(desc_doc, error, "ixmlPrintDocument failed\n");
        cJSON *_doc_sig = bytes_to_json_string(sign(sk_ra,
            (unsigned char *)desc_doc,
            doc_size));
        supnp_verify(_doc_sig,
            error,
            "Description Signature exporting failed\n");
        cJSON_AddItemToObject(cap_token, CT_DESC_SIG, _doc_sig);
    }

    /**
     * For each service in service_list do
     *   service_sig = sign(sk_pk, hash(service_id));
     *   capt_token.add_Service(service_sig, service_type);
     */
    service_list = get_service_list(info->desc_doc);
    supnp_verify(service_list,
        error,
        "Couldn't find tagname '%s' in device description document.\n",
        SERVICE_LIST);
    cJSON *_services = cJSON_CreateObject();
    supnp_verify(_services, error, "Couldn't create services array\n");
    cJSON_AddItemToObject(cap_token, CT_SERVICES, _services);
    for (size_t i = 0; i < ixmlNodeList_length(service_list); ++i) {
        IXML_Node *service = ixmlNodeList_item(service_list, i);
        IXML_NodeList *service_nodes = ixmlNode_getChildNodes(service);
        supnp_verify(
            (service_nodes) && (ixmlNodeList_length(service_nodes) > 0),
            loop_cleanup,
            "Couldn't find child nodes in service node.\n");
        const char *_service_id = NULL;
        const char *_service_type = NULL;
        for (size_t j = 0; j < ixmlNodeList_length(service_nodes); ++j) {
            IXML_Node *node = ixmlNodeList_item(service_nodes, j);
            if (node == NULL) {
                continue;
            }
            if (strcmp(ixmlNode_getNodeName(node), SERVICE_ID) == 0) {
                _service_id = ixmlNode_getNodeValue(node);
            } else if (strcmp(ixmlNode_getNodeName(node), SERVICE_TYPE) == 0) {
                _service_type = ixmlNode_getNodeValue(node);
            }
        }

        // todo: why null?
        supnp_verify((_service_id) && (_service_type),
            loop_cleanup,
            "Couldn't find tagname '%s' or '%s' in service node.\n",
            SERVICE_ID,
            SERVICE_TYPE);
        cJSON *_service_sig = bytes_to_json_string(sign(sk_ra,
            (unsigned char *)_service_id,
            strlen(_service_id)));
        cJSON_AddItemToObject(cap_token, _service_type, _service_sig);

    loop_cleanup:
        freeif2(service_nodes, ixmlNodeList_free);
    }

    /* Sign the cap token's content */
    cap_token_content = cJSON_PrintUnformatted(cap_token);
    cJSON *_content_sig = bytes_to_json_string(sign(sk_ra,
        (unsigned char *)cap_token_content,
        strlen(cap_token_content)));
    supnp_verify(_content_sig,
        error,
        "Signing Cap Token content failed\n");
    cJSON_AddItemToObject(cap_token, RA_SIG, _content_sig);

    char *test = cJSON_Print(cap_token);

    ret = SUPNP_E_SUCCESS;
    goto success;

error:
    free_cap_token(cap_token);

success:
    freeif(cap_token_content);
    freeif(desc_doc);
    freeif(concatenate_uri);
    freeif2(service_list, ixmlNodeList_free);
    return cap_token;
}

void free_cap_token(cJSON *cap_token)
{
    freeif2(cap_token, cJSON_Delete);
}


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* ENABLE_SUPNP */
