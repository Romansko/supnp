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
#include <stddef.h>

/* Forward decleration <openssl/types.h> */
typedef struct evp_pkey_st EVP_PKEY;

#ifdef ENABLE_SUPNP

#ifdef __cplusplus
extern "C" {
#endif


typedef struct device_info_t
{
    char* desc_doc_uri;
    char* cap_token_uri;
    char* desc_doc;
    size_t desc_doc_size;
} device_info_t;

typedef struct cap_token_t
{
    uint32_t ID;
    unsigned char* RA_PK; // RA Public Key

    unsigned char* DESC_SIG; // Description Signature  (sha256(Description Document))
    unsigned char* ADV_SIG; // Advertisment Signature (sha256(Cap Token URI))
    unsigned char* RA_SIG; // RA Signature           (sha256(Cap Token Content))
} cap_token_t;


UPNP_EXPORT_SPEC uint32_t random_id();

UPNP_EXPORT_SPEC void free_cap_token(cap_token_t* token);

UPNP_EXPORT_SPEC cap_token_t* generate_cap_token_sd(const device_info_t* info, EVP_PKEY* sk_ra);

UPNP_EXPORT_SPEC cap_token_t* generate_cap_token_cp(device_info_t* info, EVP_PKEY* sk_ra);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */

#endif /* SUPNP_CAPTOKEN_H */
