/*!
* \addtogroup SUPnP
 *
 * \file supnp_captoken.h
 *
 * \brief Header file for SUPnP CapToken algorithms.
 *
 * \author Roman Koifman
 */
#ifndef SUPNP_CAPTOKEN_H
#define SUPNP_CAPTOKEN_H

#include <ixml.h>

#include "UpnpGlobal.h" /* for UPNP_EXPORT_SPEC */
#include "upnpconfig.h"
#include "stdint.h"
#include <stddef.h>

#ifdef ENABLE_SUPNP

/* Forward decleration */
typedef struct evp_pkey_st EVP_PKEY;
typedef struct cJSON cJSON;
typedef struct _IXML_Document IXML_Document;
typedef struct _IXML_NodeList IXML_NodeList;

/* Cap Token related */
#define ID_SIZE       11  /* As presented by the paper */
#define SD_TYPE       "SERVICE-DEVICE"
#define CP_TYPE       "CONTROL-POINT"
#define CT_ID         "ID"
#define CT_TIMESTAMP  "ISSUER-INSTANT"
#define RA_PK         "RA-PK"
#define SD_PK         "SD-PK"
#define CP_PK         "CP-PK"
#define RA_SIG        "RA-SIG"
#define CT_TYPE       "TYPE"
#define CT_ADV_SIG    "ADVERTISEMENT-SIG"
#define CT_DESC_SIG   "DESCRIPTION-SIG"
#define CT_SERVICES   "SERVICES"
#define CT_LOC_SIG    "LOCATION-SIG"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _EDeviceType
{
    DEVICE_TYPE_SD = 0,
    DEVICE_TYPE_CP
} EDeviceType;

typedef struct _device_info_t
{
    EDeviceType device_type;
    EVP_PKEY* pk;
    char* desc_doc_uri;
    char* cap_token_uri;
    IXML_Document* desc_doc;
    size_t desc_doc_size;
} device_info_t;

UPNP_EXPORT_SPEC cJSON* json_string(char* string);

UPNP_EXPORT_SPEC cJSON* bytes_to_json_string(unsigned char* bytes);

UPNP_EXPORT_SPEC cJSON* get_timestamp();

UPNP_EXPORT_SPEC IXML_NodeList* get_service_list(IXML_Document* doc);

UPNP_EXPORT_SPEC cJSON* generate_cap_token(const device_info_t* info, EVP_PKEY* sk_ra);

UPNP_EXPORT_SPEC void free_cap_token(cJSON* cap_token);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */

#endif /* SUPNP_CAPTOKEN_H */
