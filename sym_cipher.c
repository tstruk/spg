/*************************************************************************
 * Small Privacy Guard
 * Copyright (C) Tadeusz Struk 2009-2022 <tstruk@gmail.com>
 *
 * This is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * It is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 *
 * <http://www.gnu.org/licenses/>
 *
 *************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/blowfish.h>

#include "defs.h"
#include "sym_cipher.h"


/*
 * Symmetric ciphers names
 */
const char* cipher_names[] =
{
    "Blowfish",
    "AES",
    NULL
};

/*
 * Private context structure for
 * blowfish cipher
 */
typedef struct blowfish_ctx_s
{

    BF_KEY key;
    unsigned char iv;
    int num;

} blowfish_ctx_t;

/*
 * Private encrypt rutine for
 * blowfish cipher
 */
static status blowfish_encrypt(sym_cipher_hdl_t* cipher_hdl, void* in, void* out, size_t len)
{
    blowfish_ctx_t *bf_ctx = (blowfish_ctx_t*)cipher_hdl->ctx;
    BF_cfb64_encrypt(in, out, len, &bf_ctx->key, &bf_ctx->iv, &bf_ctx->num, BF_ENCRYPT);
    return SUCCESS;
}

/*
 * Private decrypt rutine for
 * blowfish cipher
 */
static status blowfish_decrypt(sym_cipher_hdl_t* cipher_hdl, void* in, void* out, size_t len)
{
    blowfish_ctx_t *bf_ctx = (blowfish_ctx_t*)cipher_hdl->ctx;
    BF_cfb64_encrypt(in, out, len, &bf_ctx->key, &bf_ctx->iv, &bf_ctx->num, BF_DECRYPT);
    return SUCCESS;

}

/*
 * Private uninit rutine for
 * blowfish cipher
 */
static status blowfish_uninit(sym_cipher_hdl_t* cipher_hdl)
{
    FREE(cipher_hdl->ctx);
    cipher_hdl->encrypt = NULL;
    cipher_hdl->decrypt = NULL;
    cipher_hdl->uninit = NULL;
    return SUCCESS;
}

/*
 * sym_cipher_init
 */
status sym_cipher_init(sym_cipher_hdl_t** cipher_hdl, sym_cipher cipher, void* key, size_t key_len)
{
    status stat = SUCCESS;
    CHECK_PARAM(cipher_hdl);
    CHECK_PARAM(key);
    sym_cipher_hdl_t* c_ptr = NULL;

    *cipher_hdl = malloc(sizeof(sym_cipher_hdl_t));
    if (!(*cipher_hdl))
    {
        ERROR_LOG("Memory allocation failed");
        return FAIL;
    }

    c_ptr = *cipher_hdl;

    switch (cipher)
    {
    case SYM_CIPHER_BLOWFISH:
    {
        blowfish_ctx_t *bf_ctx = malloc(sizeof(blowfish_ctx_t));
        if (!bf_ctx)
        {
            ERROR_LOG("Memory allocation failed");
            FREE(cipher_hdl);
            return FAIL;
        }
        BF_set_key(&bf_ctx->key, key_len, key);
        bf_ctx->num = 0;
        bf_ctx->iv = 0;
        c_ptr->ctx = bf_ctx;
        c_ptr->encrypt = blowfish_encrypt;
        c_ptr->decrypt = blowfish_decrypt;
        c_ptr->uninit = blowfish_uninit;
    }
    break;
    case SYM_CIPHER_AES:
        stat = NOT_IMPLEMENTED;
        break;
    default:
        stat = BAD_PARAMS;
        break;
    }
    return stat;
}

/*
 * sym_cipher_encrypt
 */
status sym_cipher_encrypt(sym_cipher_hdl_t* cipher_hdl, void* in, void* out, size_t len)
{
    return cipher_hdl->encrypt(cipher_hdl, in, out, len);
}

/*
 * sym_cipher_decrypt
 */
status sym_cipher_decrypt(sym_cipher_hdl_t* cipher_hdl, void* in, void* out, size_t len)
{
    return cipher_hdl->decrypt(cipher_hdl, in, out, len);
}

/*
 * sym_cipher_close
 */
status sym_cipher_close(sym_cipher_hdl_t* cipher_hdl)
{
    status stat = cipher_hdl->uninit(cipher_hdl);
    FREE(cipher_hdl);
    return stat;
}
/*
 * Function: list_ciphers
 */
void sym_cipher_list(void)
{
    char** tab_ptr = (char**)cipher_names;
    int i = 0;
    while (NULL != *tab_ptr)
    {
        printf("%2d. %s\n", i, *tab_ptr++);
        i++;
    }
    return;
}



