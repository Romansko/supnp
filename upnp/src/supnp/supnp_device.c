/*!
 * \addtogroup SUPnP
 *
 * \file supnp_device.c
 *
 * \brief source file for SUPnP device logics.
 *
 * \author Roman Koifman
 */
#include "supnp_device.h"
#include "supnp_err.h"
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <ixml.h>
#include <cJSON/cJSON.h>

#ifdef ENABLE_SUPNP

#ifdef __cplusplus
extern "C" {
#endif

const char* supnp_device_type_str(const EDeviceType type)
{
    switch (type)
    {
    case DEVICE_TYPE_SD:
        return "SD";
    case DEVICE_TYPE_CP:
        return "CP";
    default:
        return "";
    }
}

int supnp_verify_device(const supnp_device_t* p_dev)
{
    int ret = SUPNP_DEV_ERR;
    supnp_verify(p_dev != NULL, end, "NULL device\n");
    supnp_verify(p_dev->type == DEVICE_TYPE_SD || p_dev->type == DEVICE_TYPE_CP, end, "Invalid device type\n");
    supnp_verify(p_dev->pk != NULL, end, "NULL public key\n");
    supnp_verify(p_dev->sk != NULL, end, "NULL private key\n");
    supnp_verify(p_dev->cert != NULL, end, "NULL certificate\n");
    supnp_verify(p_dev->desc_doc_uri != NULL, end, "NULL description document URI\n");
    supnp_verify(p_dev->cap_token_uri != NULL, end, "NULL cap token URI\n");
    supnp_verify(p_dev->desc_doc != NULL, end, "NULL description document\n");
    supnp_verify(p_dev->supnp_doc != NULL, end, "NULL supnp document\n");
    ret = SUPNP_DEV_OK;
end:
    return ret;
}

void supnp_free_device_content(supnp_device_t* p_dev)
{
    if (p_dev == NULL)
        return; /* Do Nothing */
    freeif2(p_dev->pk, EVP_PKEY_free);
    freeif2(p_dev->sk, EVP_PKEY_free);
    freeif2(p_dev->cert, X509_free);
    freeif(p_dev->desc_doc_uri);
    freeif(p_dev->cap_token_uri);
    freeif2(p_dev->desc_doc, ixmlDocument_free);
    freeif2(p_dev->supnp_doc, cJSON_Delete);
}

void supnp_free_device(supnp_device_t** pp_dev)
{
    if (pp_dev == NULL)
        return; /* Do Nothing */
    supnp_free_device_content(*pp_dev);
    freeif(*pp_dev);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */
