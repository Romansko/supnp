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
#include <openssl/evp.h>
#include <openssl/sha.h>     /* For SHA256_DIGEST_LENGTH  */
#include <stdlib.h>
#include <string.h>


#ifdef ENABLE_SUPNP

#ifdef __cplusplus
extern "C" {
#endif

uint32_t random_id()
{
    uint32_t id = 0;
    unsigned char *nonce = generate_nonce(sizeof(uint32_t));
    supnp_verify(nonce != NULL, cleanup, "generate_nonce failed\n");
    id = *(uint32_t *)nonce;
cleanup:
    freeif(nonce);
    return id;
}


cap_token_t *generate_cap_token_sd(device_info_t *info, EVP_PKEY *ra_pkey)
{
    // todo verify device_info
    int ret;
    cap_token_t *cap_token = NULL;
    unsigned char * uri_hash = NULL;


    supnp_verify(info != NULL, cleanup, "NULL sd_info\n");
    supnp_verify(ra_pkey != NULL, cleanup, "NULL ra_pkey\n");

    cap_token = (cap_token_t *)malloc(sizeof(cap_token_t));
    supnp_verify(cap_token != NULL, cleanup, "malloc failed\n");

    cap_token->ID = random_id();
    supnp_verify(cap_token->ID != 0, cleanup, "random_id failed\n");

    cap_token->RA_PK = public_key_to_bytes(ra_pkey, &ret);
    supnp_verify(cap_token->RA_PK != NULL, cleanup, "public_key_to_bytes failed\n");

    /**
     * For each service in service_list do
     *   service_sig = sign(sk_pk, hash(service.description));
     *   capt_token.add_Service(service_sig, service_type);
     */
    uri_hash = calloc(SHA256_DIGEST_LENGTH, 1);
    supnp_verify(cap_token->DESC_SIG != NULL, cleanup, "DESC_SIG calloc failed\n");
    ret = do_sha256((const unsigned char *)info->desc_doc_uri, strlen(info->desc_doc_uri), uri_hash);

    // ret == ok
    cap_token->DESC_SIG = uri_hash;

cleanup:
    freeif(cap_token);
    freeif(uri_hash);

success:
    return cap_token;
}

cap_token_t* generate_cap_token_cp(device_info_t* info, EVP_PKEY *ra_pkey)
{
    int ret;
    cap_token_t *cap_token = NULL;

    // todo verify device_info

    return cap_token;
}


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* ENABLE_SUPNP */
