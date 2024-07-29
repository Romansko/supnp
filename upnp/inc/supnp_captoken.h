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
#include <openssl/types.h>

#ifdef ENABLE_SUPNP

#ifdef __cplusplus
extern "C" {
#endif


typedef struct device_info_t
{
    const char* ip;
    uint16_t port;
    void * desc_doc;
    char * desc_doc_uri;
} device_info_t;

typedef struct sd_cap_token_t
{
    uint32_t id;
    const unsigned char* ra_pk; // RA Public Key
} sd_cap_token_t;


typedef struct cp_cap_token_t
{
    uint32_t id;
    const unsigned char* ra_pk; // RA Public Key
} cp_cap_token_t;


UPNP_EXPORT_SPEC uint32_t random_id();

UPNP_EXPORT_SPEC sd_cap_token_t* generate_cap_token_sd(device_info_t* info, EVP_PKEY *ra_pkey);

UPNP_EXPORT_SPEC cp_cap_token_t* generate_cap_token_cp(device_info_t* info, EVP_PKEY *ra_pkey);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */

#endif /* SUPNP_CAPTOKEN_H */
