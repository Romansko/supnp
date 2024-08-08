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

#include "UpnpGlobal.h" /* for UPNP_EXPORT_SPEC */
#include "upnpconfig.h"

#ifdef ENABLE_SUPNP

/* Forward decleration */
typedef struct evp_pkey_st EVP_PKEY;
typedef struct cJSON cJSON;
typedef struct _supnp_device_t supnp_device_t;

/* Cap Token related */
#define ID_SIZE       11  /* As presented by the paper */
#define SD_TYPE_STR   "SERVICE-DEVICE"
#define CP_TYPE_STR   "CONTROL-POINT"
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
#define CT_URI_SIG    "LOCATION-SIG"

#ifdef __cplusplus
extern "C" {
#endif


UPNP_EXPORT_SPEC cJSON* string_to_json_string(char* string);

UPNP_EXPORT_SPEC cJSON* bytes_to_json_string(unsigned char* bytes);

UPNP_EXPORT_SPEC cJSON* get_timestamp();

UPNP_EXPORT_SPEC cJSON* generate_cap_token(const supnp_device_t* dev, EVP_PKEY* sk_ra);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */

#endif /* SUPNP_CAPTOKEN_H */
