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
#include "stdint.h"

/* Forward decleration <openssl/types.h> */
typedef struct evp_pkey_st EVP_PKEY;

#ifdef ENABLE_SUPNP

#ifdef __cplusplus
extern "C" {
#endif


typedef struct device_info_t
{
    const char* ip;
    uint16_t port;
    void * desc_doc;
    const char * desc_doc_uri;
} device_info_t;

typedef struct cap_token_t
{
    uint32_t ID;
    const unsigned char * RA_PK; // RA Public Key

    const unsigned char * DESC_SIG; // Device Description URI Signature
} cap_token_t;


UPNP_EXPORT_SPEC uint32_t random_id();

UPNP_EXPORT_SPEC cap_token_t* generate_cap_token_sd(device_info_t* info, EVP_PKEY *ra_pkey);

UPNP_EXPORT_SPEC cap_token_t* generate_cap_token_cp(device_info_t* info, EVP_PKEY *ra_pkey);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */

#endif /* SUPNP_CAPTOKEN_H */
