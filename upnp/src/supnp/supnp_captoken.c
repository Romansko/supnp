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
#include <stdlib.h>
#include <string.h>


#ifdef ENABLE_SUPNP

#ifdef __cplusplus
extern "C" {
#endif

uint32_t random_id()
{
    unsigned char *nonce = generate_nonce(sizeof(uint32_t));
    supnp_verify(, (nonce != NULL), 0, "generate_nonce failed\n");
    uint32_t id = *(uint32_t *)nonce;
    free(nonce);
    return id;
}


sd_cap_token_t *generate_cap_token_sd(device_info_t *info, EVP_PKEY *ra_pkey)
{
    // todo verify device_info

    int ret;
    sd_cap_token_t *cap_token = NULL;
    supnp_verify(, (info != NULL), NULL, "NULL sd_info\n");
    supnp_verify(, (ra_pkey != NULL), NULL, "NULL ra_pkey\n");

    cap_token = (sd_cap_token_t *)malloc(sizeof(sd_cap_token_t));
    supnp_verify(, (cap_token != NULL), NULL, "malloc failed\n");

    cap_token->id = random_id();
    supnp_verify(free(cap_token),
        (cap_token->id != 0),
        NULL,
        "random_id failed\n");

    cap_token->ra_pk = public_key_to_bytes(ra_pkey, &ret);
    supnp_verify(free(cap_token),
        (cap_token->ra_pk != NULL),
        NULL,
        "public_key_to_bytes failed\n");

    /**
     * For each service in service_list do
     *   service_sig = sign(sk_pk, hash(service.description));
     *   capt_token.add_Service(service_sig, service_type);
     */

    // do_sha256(info->desc_doc_uri, strlen(info->desc_doc_uri),

    return cap_token;
}

cp_cap_token_t* generate_cap_token_cp(device_info_t* info, EVP_PKEY *ra_pkey)
{
    int ret;
    cp_cap_token_t *cap_token = NULL;

    // todo verify device_info

    return cap_token;
}


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* ENABLE_SUPNP */
