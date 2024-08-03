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

void free_cap_token(cap_token_t *token)
{
    supnp_verify(token != NULL, error, "NULL cap token\n");
    freeif(token->RA_PK);
    freeif(token->ADV_SIG);
    freeif(token->DESC_SIG);
    freeif(token->RA_SIG);
    freeif(token);
error:
    /* Do nothing */

}


cap_token_t *generate_cap_token_sd(const device_info_t *info, EVP_PKEY *sk_ra)
{
    // todo verify device_info
    int ret = OPENSSL_FAILURE;
    cap_token_t *cap_token = NULL;
    char *concatenate_uri = NULL; // description uri || token uri
    unsigned char *token_content = NULL;
    size_t token_content_size = 0;
    size_t ra_pk_size = 0;
    size_t tmp_size = 0;

    supnp_verify(info != NULL, error, "NULL sd_info\n");
    supnp_verify(sk_ra != NULL, error, "NULL ra_pkey\n");

    cap_token = (cap_token_t *)calloc(1, sizeof(cap_token_t));
    supnp_verify(cap_token != NULL,
        error,
        "cap_token memory allocation failed\n");

    /* Get ID */
    cap_token->ID = random_id();
    supnp_verify(cap_token->ID != 0, error, "random_id failed\n");
    token_content_size += sizeof(cap_token->ID);

    /* Copy RA Public Key */
    cap_token->RA_PK = public_key_to_bytes(sk_ra, &ra_pk_size);
    supnp_verify(cap_token->RA_PK != NULL,
        error,
        "public_key_to_bytes failed\n");
    token_content_size += ra_pk_size;

    /**
     * For each service in service_list do
     *   service_sig = sign(sk_pk, hash(service.description));
     *   capt_token.add_Service(service_sig, service_type);
     */

    /* Sign Device Description Document */
    cap_token->DESC_SIG = sign(sk_ra,
        (const unsigned char *)info->desc_doc,
        info->desc_doc_size);
    supnp_verify(cap_token->DESC_SIG != NULL,
        error,
        "Description Signature calculation failed\n");
    token_content_size += strlen((const char *)cap_token->DESC_SIG);

    /* Sign advertisement URI (description uri || token uri) */
    concatenate_uri = malloc(
        strlen(info->desc_doc_uri) + strlen(info->cap_token_uri) + 1);
    supnp_verify(concatenate_uri != NULL,
        error,
        "concatenate_uri memory allocation failed\n");
    strcpy(concatenate_uri, info->desc_doc_uri);
    strcat(concatenate_uri, info->cap_token_uri);
    cap_token->ADV_SIG = sign(sk_ra,
        (const unsigned char *)concatenate_uri,
        strlen(concatenate_uri));
    supnp_verify(cap_token->ADV_SIG != NULL,
        error,
        "advertisement Signature calculation failed\n");
    token_content_size += strlen((const char *)cap_token->ADV_SIG);

    /* Allocate a single buffer for the token's content */
    token_content = malloc(token_content_size);
    supnp_verify(token_content != NULL,
        error,
        "token_content memory allocation failed\n");
    unsigned char *p_token_content = token_content;

    /* Copy token's content - Without RA-SIG */
    copy_inc(p_token_content, &(cap_token->ID), sizeof(cap_token->ID));
    copy_inc(p_token_content, cap_token->RA_PK, ra_pk_size);
    copy_inc(p_token_content,
        cap_token->DESC_SIG,
        strlen((const char *)cap_token->DESC_SIG));
    copy_inc(p_token_content,
        cap_token->ADV_SIG,
        strlen((const char *)cap_token->DESC_SIG));

    /* Sign the cap token's content */
    cap_token->RA_SIG = sign(sk_ra, token_content, token_content_size);
    supnp_verify(cap_token->RA_SIG != NULL,
        error,
        "Signing Cap Token content failed\n");

    goto success;

error:
    free_cap_token(cap_token);

success:
    freeif(concatenate_uri);
    freeif(token_content);
    return cap_token;
}

cap_token_t *generate_cap_token_cp(device_info_t *info, EVP_PKEY *sk_ra)
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
