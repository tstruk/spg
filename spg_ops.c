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
#include <gcrypt.h>
#include <string.h>
#include <getopt.h>
#include <sys/stat.h>
#include <gcrypt.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <assert.h>

#include "defs.h"
#include "ec_point.h"
#include "ecc.h"
#include "curves.h"
#include "utils.h"
#include "help.h"
#include "sym_cipher.h"

/*
 * Globals
 */
#define BUFFER_SIZE 512

/*
 * generate_key
 * Generates private key on curve curve_name
 * and writes the key to file out_file in PEM format
 */
status generate_keys(char* curve_name, char* out_file)
{
    status stat = SUCCESS;
    mode_t old_umask = umask(S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    EC_private_key_t private_key;

    CHECK_PARAM(curve_name);
    CHECK_PARAM(out_file);

    FILE *file = fopen(out_file,"w");
    if (!file)
    {
        ERROR_LOG("Can not create file %s.\n", out_file);
        stat = FAIL;
    }
    if (SUCCESS == stat)
    {
        if ((stat = ec_generate_key(&private_key, curve_name)) == SUCCESS)
        {
            unsigned char key_buff[BUFFER_SIZE];
            unsigned char *buff_ptr = key_buff;
            size_t len = 0;
            unsigned int space = 0;

            if (gcry_mpi_print(GCRYMPI_FMT_USG, buff_ptr + 1,
                               BUFFER_SIZE - space, &len, private_key.pub.Q.x) == GPG_ERR_NO_ERROR)
            {
                *buff_ptr = (unsigned char) len;
                len += 1;
                buff_ptr += len;
                space += len;
                assert(BUFFER_SIZE > space);
            }
            else
            {
                ERROR_LOG("Filed to export data");
                stat = FAIL;
            }
            if ((SUCCESS == stat) && (gcry_mpi_print(GCRYMPI_FMT_USG, buff_ptr + 1,
                                      BUFFER_SIZE - space, &len, private_key.pub.Q.y) == GPG_ERR_NO_ERROR))
            {
                *buff_ptr = (unsigned char) len;
                len += 1;
                buff_ptr += len;
                space += len;
                assert(BUFFER_SIZE > space);
            }
            else
            {
                ERROR_LOG("Filed to export data");
                stat = FAIL;
            }
            if ((SUCCESS == stat) && (gcry_mpi_print(GCRYMPI_FMT_USG, buff_ptr + 1,
                                          BUFFER_SIZE - space, &len, private_key.priv) == GPG_ERR_NO_ERROR))
            {
                *buff_ptr = (unsigned char) len;
                len += 1;
                buff_ptr += len;
                space += len;
                assert(BUFFER_SIZE > space);
            }
            else
            {
                ERROR_LOG("Filed to export data");
                stat = FAIL;
            }
            if (SUCCESS == stat)
            {
                *buff_ptr = (unsigned char) strlen(private_key.pub.c.name);
                buff_ptr += 1;
                memcpy(buff_ptr, private_key.pub.c.name, strlen(private_key.pub.c.name));
                space += 1 + strlen(private_key.pub.c.name);
            }
            if ((SUCCESS == stat) && (PEM_write(file, PEM_PRV_KEY_NAME, PEM_EMPTY_STR,
                                                    (void*) key_buff, space)))
            {
                LOG("Private key generated successfully - %d bytes written to %s file\n", space, out_file);
            }
            else
            {
                ERROR_LOG("Filed to write private key (%d bytes) to %s file\n", space, out_file);
                stat = FAIL;
            }
            ec_release_key(&private_key);
        }
        else
        {
            ERROR_LOG("Keys generate failed\n");
        }
        fclose(file);
    }
    umask(old_umask);
    return stat;
}

/*
 * read_private_key
 * Reads private key from disk file in PEM format
 */
static status read_private_key(EC_private_key_t* private_key, char* in_file)
{
    status stat = SUCCESS;
    char *name = NULL, *header = NULL ;
    unsigned char *data = NULL;
    long len = 0;

    CHECK_PARAM(private_key);
    CHECK_PARAM(in_file);

    FILE *file = fopen(in_file, "r");

    if (!file)
    {
        ERROR_LOG("Can not open file %s.\n", in_file);
        stat = FAIL;
    }
    if (SUCCESS == stat)
    {
        if (PEM_read(file, &name, &header, &data, &len) == 1)
        {

            LOG("Read %d bytes from file %s\n", (int)len, in_file);
            if ((strncmp(PEM_PRV_KEY_NAME, name, strlen(PEM_PRV_KEY_NAME))) == 0)
            {
                LOG("The file is an SPG private key in PEM format\n");
            }
            else
            {
                ERROR_LOG("The file %s in not an SPG private key in PEM format\n", in_file);
                FREE(data);
                FREE(name);
                FREE(header);
                stat = FAIL;
            }
        }
        else
        {
            ERROR_LOG("PEM_read failed to read %s file\n", in_file);
            stat = FAIL;
        }
        fclose(file);
        if (SUCCESS == stat)
        {
            unsigned char size = 0;
            size_t size_scanned = 0;
            unsigned char *buff_ptr = data;

            size = *buff_ptr;
            buff_ptr += 1;

            /*
             * Data read from the file
             * now going to scan data into private key
             */
            /*
             * Scan public key x
             */
            if (gcry_mpi_scan(&private_key->pub.Q.x, GCRYMPI_FMT_USG,
                                buff_ptr, (size_t) size, &size_scanned) != GPG_ERR_NO_ERROR)
            {
                stat = FAIL;
            }
            if (SUCCESS == stat)
            {
                /*
                 * Scan public key y
                 */
                buff_ptr += size;
                size = *buff_ptr;
                buff_ptr += 1;
                if (gcry_mpi_scan(&private_key->pub.Q.y, GCRYMPI_FMT_USG,
                                    buff_ptr, (size_t) size, &size_scanned) != GPG_ERR_NO_ERROR)
                {
                    stat = FAIL;
                }
            }
#ifdef JACOBIAN_COORDINATES
            private_key->pub.Q.z = mpi_new(0);
            mpi_set_ui(private_key->pub.Q.z, 1);
#endif
            if (SUCCESS == stat)
            {
                /*
                 * Scan private key
                 */
                buff_ptr += size;
                size = *buff_ptr;
                buff_ptr += 1;
                if (gcry_mpi_scan(&private_key->priv, GCRYMPI_FMT_USG,
                                    buff_ptr, (size_t) size, &size_scanned) != GPG_ERR_NO_ERROR)
                {
                    stat = FAIL;
                }

            }
            if (SUCCESS == stat)
            {
                char curve_name[1024];
                curve c;
                /*
                 * Scan curve data
                 */
                buff_ptr += size;
                size = *buff_ptr;
                buff_ptr += 1;
                memcpy(curve_name, buff_ptr, (size_t) size);
                curve_name[ (size_t)size ] = '\0';
                stat = get_curve_by_name(&c, curve_name);
                if (SUCCESS == stat)
                {
                    private_key->pub.c = c;
                }
                else
                {
                    ERROR_LOG("Curve not found %s. Failed to read private key\n", curve_name);
                }
            }
            FREE(data);
            FREE(name);
            FREE(header);
        }
    }
    return stat;
}

/*
 *
 */
static status write_public_key(EC_public_key_t* public_key, char* out_file)
{
    status stat = SUCCESS;
    CHECK_PARAM(public_key);
    CHECK_PARAM(out_file);

    FILE *file = fopen(out_file,"w");
    if (!file)
    {
        ERROR_LOG("Can not create file %s.\n", out_file);
        stat = FAIL;
    }
    if (SUCCESS == stat)
    {
        unsigned char key_buff[BUFFER_SIZE];
        unsigned char *buff_ptr = key_buff;
        size_t len = 0;
        unsigned int space = 0;
        if (gcry_mpi_print(GCRYMPI_FMT_USG, buff_ptr + 1,
                           BUFFER_SIZE - space, &len, public_key->Q.x) == GPG_ERR_NO_ERROR)
        {
            *buff_ptr = (unsigned char) len;
            len += 1;
            buff_ptr += len;
            space += len;
            assert(BUFFER_SIZE > space);
        }
        else
        {
            ERROR_LOG("Filed to export data");
            stat = FAIL;
        }
        if ((SUCCESS == stat) && (gcry_mpi_print(GCRYMPI_FMT_USG, buff_ptr + 1,
                                      BUFFER_SIZE - space, &len, public_key->Q.y) == GPG_ERR_NO_ERROR))
        {
            *buff_ptr = (unsigned char) len;
            len += 1;
            buff_ptr += len;
            space += len;
            assert(BUFFER_SIZE > space);
        }
        else
        {
            ERROR_LOG("Filed to export data");
            stat = FAIL;
        }
        if (SUCCESS == stat)
        {
            *buff_ptr = (unsigned char) strlen(public_key->c.name);
            buff_ptr += 1;
            memcpy(buff_ptr, public_key->c.name, strlen(public_key->c.name));
            space += 1 + strlen(public_key->c.name);
        }
        if ((SUCCESS == stat) && (PEM_write(file, PEM_PUB_KEY_NAME, PEM_EMPTY_STR,
                                                (void*) key_buff, space)))
        {
            LOG("Public key exported successfully - %d bytes written to %s file\n", space, out_file);
        }
        else
        {
            ERROR_LOG("Filed to write private key (%d bytes) to %s file\n", space, out_file);
            stat = FAIL;
        }
    }
    if (file)
        fclose(file);
    return stat;
}

/*
 *
 */
static status read_public_key (EC_public_key_t* public_key, char* in_file)
{
    status stat = SUCCESS;
    char *name = NULL, *header = NULL ;
    unsigned char *data = NULL;
    long len = 0;
    CHECK_PARAM(public_key);
    CHECK_PARAM(in_file);

    FILE *file = fopen(in_file, "r");

    if (!file)
    {
        ERROR_LOG("Can not open file %s.\n", in_file);
        stat = FAIL;
    }
    if (SUCCESS == stat)
    {
        if (PEM_read(file, &name, &header, &data, &len) == 1)
        {
            LOG("Read %d bytes from file %s\n", (int)len, in_file);
            if ((strncmp(PEM_PUB_KEY_NAME, name, strlen(PEM_PUB_KEY_NAME))) == 0)
            {
                LOG("The file is an SPG public key in PEM format\n");
            }
            else
            {
                ERROR_LOG("The file %s is not a SPG public key in PEM format\n", in_file);
                FREE(data);
                FREE(name);
                FREE(header);
                stat = FAIL;
            }
        }
        else
        {
            ERROR_LOG("PEM_read failed to read %s file\n", in_file);
            stat = FAIL;
        }
        fclose(file);
        if (SUCCESS == stat)
        {
            unsigned char size = 0;
            size_t size_scanned = 0;
            unsigned char *buff_ptr = data;

            size = *buff_ptr;
            buff_ptr += 1;

            /*
             * Data read from the file
             * now going to scan data into public key
             */
            /*
             * Scan public key x
             */
            if (gcry_mpi_scan(&public_key->Q.x, GCRYMPI_FMT_USG,
                                buff_ptr, (size_t) size, &size_scanned) != GPG_ERR_NO_ERROR)
            {
                stat = FAIL;
            }
            if (SUCCESS == stat)
            {
                /*
                 * Scan public key y
                 */
                buff_ptr += size;
                size = *buff_ptr;
                buff_ptr += 1;
                if (gcry_mpi_scan(&public_key->Q.y, GCRYMPI_FMT_USG,
                                    buff_ptr, (size_t) size, &size_scanned) != GPG_ERR_NO_ERROR)
                {
                    stat = FAIL;
                }
            }
#ifdef JACOBIAN_COORDINATES
            public_key->Q.z = mpi_new(0);
            mpi_set_ui(public_key->Q.z, 1);
#endif
            if (SUCCESS == stat)
            {
                char curve_name[BUFFER_SIZE];
                curve c;
                /*
                 * Scan curve data
                 */
                buff_ptr += size;
                size = *buff_ptr;
                buff_ptr += 1;
                memcpy(curve_name, buff_ptr, (size_t) size);
                curve_name[ (size_t)size ] = '\0';
                stat = get_curve_by_name(&c, curve_name);
                if (SUCCESS == stat)
                {
                    public_key->c = c;
                }
                else
                {
                    ERROR_LOG("Curve not found %s. Failed to read public key\n", curve_name);
                }
            }
            FREE(data);
            FREE(name);
            FREE(header);
        }
    }
    return stat;
}

/*
 *
 */
status export_public_key (char* in_file, char* out_file)
{
    status stat = SUCCESS;
    EC_private_key_t private_key;

    if ((stat = read_private_key(&private_key, in_file)) != SUCCESS)
    {
        return stat;
    }
    stat = write_public_key(&private_key.pub, out_file);
    ec_release_key(&private_key);
    return stat;
}

/*
 *
 */
static status write_signature(EC_signature_t* signature, char* output)
{
    status stat = SUCCESS;
    unsigned char key_buff[BUFFER_SIZE];
    unsigned char *buff_ptr = key_buff;
    size_t len = 0;
    unsigned int space = 0;
    FILE *out_file = fopen(output, "w");
    if (!out_file)
    {
        ERROR_LOG("Can not create signature file %s.\n", output);
        stat = FAIL;
    }
    if ((SUCCESS == stat) && (gcry_mpi_print(GCRYMPI_FMT_USG, buff_ptr + 1,
                                  BUFFER_SIZE - space, &len, signature->r) == GPG_ERR_NO_ERROR))
    {
        *buff_ptr = (unsigned char) len;
        len += 1;
        buff_ptr += len;
        space += len;
        assert(BUFFER_SIZE > space);
    }
    else
    {
        ERROR_LOG("Filed to export data");
        stat = FAIL;
    }
    if ((SUCCESS == stat) && (gcry_mpi_print(GCRYMPI_FMT_USG, buff_ptr + 1,
                                  BUFFER_SIZE - space, &len, signature->s) == GPG_ERR_NO_ERROR))
    {
        *buff_ptr = (unsigned char) len;
        len += 1;
        buff_ptr += len;
        space += len;
        assert(BUFFER_SIZE > space);
    }
    else
    {
        ERROR_LOG("Filed to export data");
        stat = FAIL;
    }
    if ((SUCCESS == stat) && (PEM_write(out_file, PEM_SIGN_NAME, PEM_EMPTY_STR,
                                            (void*) key_buff, space)))
    {
        LOG("Signature generated successfully - %d bytes written to %s file\n", space, output);
    }
    else
    {
        ERROR_LOG("Filed to wirte signature (%d bytes) to %s file\n", space, output);
        stat = FAIL;
    }
    if (out_file)
        fclose(out_file);

    return stat;
}

/*
 *
 */
static status read_signature(EC_signature_t *sign, char* sign_file)
{
    status stat = SUCCESS;
    char *name = NULL, *header = NULL ;
    unsigned char *data = NULL;
    long len = 0;
    CHECK_PARAM(sign);
    CHECK_PARAM(sign_file);

    FILE *file = fopen(sign_file, "r");

    if (!file)
    {
        ERROR_LOG("Can not open signature file %s.\n", sign_file);
        stat = FAIL;
    }
    if (SUCCESS == stat)
    {
        if (PEM_read(file, &name, &header, &data, &len) == 1)
        {
            LOG("Read %d bytes from signature file %s\n", (int)len, sign_file);
            if ((strncmp(PEM_SIGN_NAME, name, strlen(PEM_SIGN_NAME))) == 0)
            {
                LOG("The file is a signature in PEM format\n");
            }
            else
            {
                ERROR_LOG("The file %s in not a signature in PEM format\n", sign_file);
                FREE(data);
                FREE(name);
                FREE(header);
                stat = FAIL;
            }
        }
        else
        {
            ERROR_LOG("PEM_read failed to read %s file\n", sign_file);
            stat = FAIL;
        }
        fclose(file);
        if (SUCCESS == stat)
        {
            unsigned char size = 0;
            size_t size_scanned = 0;
            unsigned char *buff_ptr = data;

            size = *buff_ptr;
            buff_ptr += 1;

            /*
             * Data read from the file
             * now going to scan data into signature
             */
            /*
             * Scan public key r
             */
            if (gcry_mpi_scan(&sign->r, GCRYMPI_FMT_USG,
                                buff_ptr, (size_t) size, &size_scanned) != GPG_ERR_NO_ERROR)
            {
                stat = FAIL;
            }
            if (SUCCESS == stat)
            {
                /*
                 * Scan public s
                 */
                buff_ptr += size;
                size = *buff_ptr;
                buff_ptr += 1;
                if (gcry_mpi_scan(&sign->s, GCRYMPI_FMT_USG,
                                    buff_ptr, (size_t) size, &size_scanned) != GPG_ERR_NO_ERROR)
                {
                    stat = FAIL;
                }
            }
            FREE(data);
            FREE(name);
            FREE(header);
        }
    }
    return stat;
}

/*
 *
 */
status generate_signature(char* key, char* output, char* message)
{
    status stat = SUCCESS;
    EC_private_key_t priv_key;
    EC_signature_t sign;
    void* msg_buffer = NULL;
    long msg_size = 0;
    int dummy;
    char signature_file_name[MAX_FILE_NAME_SIZE];
    FILE *msg = NULL, *sign_file = NULL;

    CHECK_PARAM(key);
    CHECK_PARAM(message);
    msg = fopen(message, "r");
    if (!msg)
    {
        ERROR_LOG("Can not open message file %s\n", message);
        return FAIL;
    }

    fseek(msg, 0, SEEK_END);
    msg_size = ftell(msg);

    if (MAX_MSG_SIZE < msg_size)
    {
        ERROR_LOG("Max message size is " MAX_MSG_SIZE_STR "\n");
        fclose(msg);
        return FAIL;
    }

    if(NULL == output)
    {
        strcpy(signature_file_name, message);
        strcat(signature_file_name, SIGNATURE_FILE_SUFFIX);
    }
    else
    {
        strcpy(signature_file_name, output);
    }
    sign_file = fopen(signature_file_name, "w");
    if (!sign_file)
    {
        ERROR_LOG("Can not create signature file %s\n", signature_file_name);
        fclose(msg);
        return FAIL;
    }
    fclose(sign_file);

    fseek(msg, 0, SEEK_SET);

    msg_buffer = malloc((size_t) msg_size);
    if (! msg_buffer)
    {
        ERROR_LOG("Memory allocation failed to allocate %d bytes \n", (int) msg_size);
        fclose(msg);
        return FAIL;
    }
    dummy = fread(msg_buffer, 1, (size_t) msg_size, msg);

    if ((stat = read_private_key(&priv_key, key)) != SUCCESS)
    {
        return stat;
    }

    stat = ec_generate_signature(&priv_key, &sign, msg_buffer, (size_t) msg_size);

    /*
     * Free private key - we won't need it anymore
     */
    ec_release_key(&priv_key);

    free(msg_buffer);

    if (stat == SUCCESS)
        stat = write_signature(&sign, signature_file_name);

    ec_release_signature(&sign);
    return stat;
}

/*
 *
 */
status verify_signature(char* pub_key_name, char* output, char* message)
{
    status stat = SUCCESS;
    EC_public_key_t pub_key;
    EC_signature_t sign;
    void* msg_buffer = NULL;
    long msg_size = 0;
    int dummy;

    CHECK_PARAM(pub_key_name);
    CHECK_PARAM(output);
    CHECK_PARAM(message);

    FILE *msg = fopen(message, "r");
    if (!msg)
    {
        ERROR_LOG("Can not open message file %s\n", message);
        return FAIL;
    }

    fseek(msg, 0, SEEK_END);
    msg_size = ftell(msg);

    if (MAX_MSG_SIZE < msg_size)
    {
        ERROR_LOG("Max message size is " MAX_MSG_SIZE_STR "\n");
        fclose(msg);
        return FAIL;
    }

    fseek(msg, 0, SEEK_SET);

    msg_buffer = malloc((size_t) msg_size);
    if (! msg_buffer)
    {
        ERROR_LOG("Memory allocation failed to allocate %d bytes \n", (int) msg_size);
        fclose(msg);
        return FAIL;
    }

    dummy = fread(msg_buffer, 1, (size_t) msg_size, msg);

    if ((stat = read_public_key(&pub_key, pub_key_name)) != SUCCESS)
    {
        ERROR_LOG("Failed to read public key file\n");
    }
    if ((SUCCESS == stat) &&
            ((stat = read_signature(&sign, output)) != SUCCESS))
    {
        ERROR_LOG("Failed to read signature file\n");
        ec_release_public_key(&pub_key);
    }

    if (stat == SUCCESS)
    {
        stat = ec_verify_signature(&pub_key, &sign, msg_buffer, msg_size);
        ec_release_signature(&sign);
        ec_release_public_key(&pub_key);
    }

    free(msg_buffer);
    return stat;
}

/*
 *
 */
status encrypt(char* key_file, char* file_to_encrypt)
{
    status stat = SUCCESS;
    EC_enc_key_t enc_key;
    EC_public_key_t public_key;
    char enc_file_name[MAX_FILE_NAME_SIZE];
    char plain_txt_buff[SYM_CIPHER_DATA_UNIT_SIZE];
    char cipher_txt_buff[SYM_CIPHER_DATA_UNIT_SIZE];

    FILE* f_to_enc = NULL;
    FILE* f_enc = NULL;

    unsigned char hmac_buff[SHA1_LEN];
    unsigned int hmac_len = 0;
    int dummy;

    CHECK_PARAM(key_file);
    CHECK_PARAM(file_to_encrypt);

    f_to_enc = fopen(file_to_encrypt, "rb");

    if (!f_to_enc)
    {
        ERROR_LOG("Failed to open file %s\n", file_to_encrypt);
        return FAIL;
    }
    strcpy(enc_file_name, file_to_encrypt);
    strcat(enc_file_name, ENCRYPTED_FILE_SUFFIX);

    f_enc = fopen(enc_file_name, "wb");
    if (!f_enc)
    {
        ERROR_LOG("Failed to create file %s\n", enc_file_name);
        fclose(f_to_enc);
        return FAIL;
    }

    if ((stat = read_public_key(&public_key, key_file)) != SUCCESS)
    {
        ERROR_LOG("Failed to read public key file\n");
        fclose(f_to_enc);
        fclose(f_enc);
        return FAIL;
    }
    /*
     * Asymetric part of the exercise
     * Generate symmetric key for ecnryption
     */
    if ((stat = ec_generate_enc_key(&enc_key, &public_key)) != SUCCESS)
    {
        ERROR_LOG("Failed to generate encryption key");
    }
    /*
     * if ok we first put the the R point to the output file
     * We will need to for decryption
     */
    if (SUCCESS == stat)
    {
        unsigned char buff[MAX_BIG_NUM_SIZE * 2];
        unsigned char *buff_ptr = buff;
        size_t len = 0;
        unsigned int space = 0;
        if (gcry_mpi_print(GCRYMPI_FMT_USG, buff_ptr + 1,
                           MAX_BIG_NUM_SIZE, &len, enc_key.R.x) == GPG_ERR_NO_ERROR)
        {
            *buff_ptr = (unsigned char) len;
            len += 1;
            buff_ptr += len;
            space += len;
            assert((MAX_BIG_NUM_SIZE * 2) > space);
        }
        else
        {
            ERROR_LOG("Filed to export data R.x ");
            stat = FAIL;
        }
        if (gcry_mpi_print(GCRYMPI_FMT_USG, buff_ptr + 1,
                           MAX_BIG_NUM_SIZE, &len, enc_key.R.y) == GPG_ERR_NO_ERROR)
        {
            *buff_ptr = (unsigned char) len;
            len += 1;
            buff_ptr += len;
            space += len;
            assert((MAX_BIG_NUM_SIZE * 2) > space);
        }
        else
        {
            ERROR_LOG("Filed to export data R.y ");
            stat = FAIL;
        }
        /*
         * Put point R into output file
         */
        dummy = fwrite(buff, 1, space, f_enc);
    }
    /*
     * ECC part done now the symmetric part
     * of the exercise
     * if it went OK till now encrypt the file
     * using symmetric cipher and key generated by EC
     * and authenticate the ciphet text using HMAC
     */
    if (SUCCESS == stat)
    {
        int read_write_ok = 1;
        sym_cipher_hdl_t *cipher_ctx;
        HMAC_CTX *hmac_ctx = HMAC_CTX_new();
        /*
         * Init symmetric cipher (they say that blowfish is fast so use it for now)
         * TODO take cipher as a parameter
         */

	if (!hmac_ctx)
            stat = FAIL;

        stat = sym_cipher_init(&cipher_ctx, SYM_CIPHER_BLOWFISH, enc_key.k1, enc_key.key_size);
        HMAC_Init_ex(hmac_ctx, enc_key.k1, enc_key.key_size, EVP_sha1(), NULL);

        if (SUCCESS == stat)
        {
            int read = 0;
            int written = 0;
            do
            {
                /*
                 * Get chunk of data from input file
                 */
                read = fread(plain_txt_buff, 1, SYM_CIPHER_DATA_UNIT_SIZE, f_to_enc);
                if (read)
                {
                    /*
                     * encrypt it
                     */
                    if ((stat = sym_cipher_encrypt(cipher_ctx, (void*)plain_txt_buff,
                                                    (void*)cipher_txt_buff, read)) == SUCCESS)
                    {
                        /*
                         * Put it into output file
                         */
                        written = fwrite(cipher_txt_buff, 1, read, f_enc);

                        /*
                         * Update Message Auth Code
                         */
                        HMAC_Update(hmac_ctx, (unsigned char*)cipher_txt_buff, read);

                        /*
                         * Check if everything that got read is written
                         */
                        if (read != written)
                        {
                            read_write_ok = 0;
                            stat = FAIL;
                        }
                    }
                }
                /*
                 * Loop till get to the end of input file
                 * or something bad happen
                 */
            }
            while ((! feof(f_to_enc)) && (read_write_ok) && (SUCCESS == stat));
            /*
             * If ok finalise HMAC computation and put the HMAC to the output file
             */
            if (SUCCESS == stat)
            {
                HMAC_Final(hmac_ctx, hmac_buff, &hmac_len);
                dummy = fwrite(hmac_buff, 1, hmac_len, f_enc);
                fflush(f_enc);
            }
            /*
             * Clean the symmetric cipher session
             */
            sym_cipher_close(cipher_ctx);
            HMAC_CTX_free(hmac_ctx);
        }
        else
        {
            ERROR_LOG("Failed initialise symmectic cipher\n");
        }
    }
    /*
     * We're done - clean up
     */
    ec_release_public_key(&public_key);
    ec_release_enc_key(&enc_key);
    fclose(f_to_enc);
    fclose(f_enc);
    if (SUCCESS != stat)
    {
        /*
         * Something went wrong - print info
         * and delete output file as there is probably some crap in it
         */
        INFO_LOG("File ecnryption failed\n");
        remove(enc_file_name);
    }
    else
    {
        INFO_LOG("File encrypted\n");
    }
    return stat;
}

/*
 *
 */
status decrypt(char* key_file, char* file_to_decrypt, char* output)
{
    status stat = SUCCESS;
    EC_enc_key_t enc_key;
    EC_private_key_t priv_key;
    char dec_file_name[MAX_FILE_NAME_SIZE];

    FILE* f_to_dec = NULL;
    FILE* f_dec = NULL;

    unsigned char hmac_buff[SHA1_LEN];
    unsigned char hmac_buff_from_file[SHA1_LEN];
    unsigned int hmac_len = 0;

    unsigned int big_number_size = 0;
    char big_number_buffer[MAX_BIG_NUM_SIZE];
    int dummy;

    /*
     * Validate parameters
     */
    CHECK_PARAM(key_file);
    CHECK_PARAM(file_to_decrypt);

    f_to_dec = fopen(file_to_decrypt, "rb");

    if (!f_to_dec)
    {
        ERROR_LOG("Failed to open file %s\n", file_to_decrypt);
        return FAIL;
    }
    /*
     * Not going to write and read from/to the same file in the same time
     */
    if (output && (strcmp(file_to_decrypt, output) == 0))
    {
        fclose(f_to_dec);
        ERROR_LOG("Input file and output file have to be different\n");
        return FAIL;
    }
    if (!output)
    {
        char* suffix = strstr(file_to_decrypt, ENCRYPTED_FILE_SUFFIX);
        if (suffix != NULL)
        {

            memcpy(dec_file_name, file_to_decrypt, (suffix - file_to_decrypt));
            dec_file_name[ suffix - file_to_decrypt ] = '\0';
        }
        else
        {
            ERROR_LOG(" No output file name provided \n");
            fclose(f_to_dec);
            return FAIL;
        }
    }
    else
    {
        strncpy(dec_file_name, output, MAX_FILE_NAME_SIZE);
    }
    LOG("Decrypt file %s into %s\n", file_to_decrypt, dec_file_name);

    f_dec = fopen(dec_file_name, "wb");
    if (!f_dec)
    {
        ERROR_LOG("Failed to create file %s\n", dec_file_name);
        fclose(f_to_dec);
        return FAIL;
    }

    /*
     * Read privare key from file
     */
    if ((stat = read_private_key(&priv_key, key_file)) != SUCCESS)
    {
        ERROR_LOG("Failed to read private key file\n");
        fclose(f_to_dec);
        fclose(f_dec);
        return FAIL;
    }
    else
    {
        /*
         * Read from encrypted file the R point
         */
        big_number_size = fgetc(f_to_dec);
        if(big_number_size == EOF)
        {
            /* file is empty */
            ERROR_LOG("The file to encrypt is an empty file\n");
            fclose(f_to_dec);
            fclose(f_dec);
            return FAIL;
        }
        dummy = fread(big_number_buffer, 1, (size_t) big_number_size, f_to_dec);
        if(dummy != big_number_size)
        {
            ERROR_LOG("Reading the encrypted file failed\n");
            fclose(f_to_dec);
            fclose(f_dec);
            return FAIL;

        }
        if (gcry_mpi_scan(&enc_key.R.x, GCRYMPI_FMT_USG,
                            big_number_buffer, (size_t) big_number_size, NULL) != GPG_ERR_NO_ERROR)
        {
            ERROR_LOG("Read data failed R.x");
            stat = FAIL;
        }
        else
        {
            big_number_size = fgetc(f_to_dec);
            if(big_number_size == EOF)
            {
                /* file is empty */
                ERROR_LOG("The encrypted file is corrupted\n");
                fclose(f_to_dec);
                fclose(f_dec);
                mpi_release(enc_key.R.x);
                return FAIL;
            }
            dummy = fread(big_number_buffer, 1, (size_t) big_number_size, f_to_dec);

            if(dummy != big_number_size)
            {
                ERROR_LOG("Reading the encrypted file failed\n");
                fclose(f_to_dec);
                fclose(f_dec);
                mpi_release(enc_key.R.x);
                return FAIL;
            }
            if (gcry_mpi_scan(&enc_key.R.y, GCRYMPI_FMT_USG,
                                big_number_buffer, (size_t) big_number_size, NULL) != GPG_ERR_NO_ERROR)
            {
                ERROR_LOG("Read data failed R.y");
                stat = FAIL;
            }
#ifdef JACOBIAN_COORDINATES
            else
            {
                enc_key.R.z = mpi_new(0);
                mpi_set_ui(enc_key.R.z, 1);
            }
#endif
        }
    }
    if (SUCCESS == stat)
    {
        stat = ec_generate_dec_key(&enc_key, &priv_key);
    }
    if (SUCCESS == stat)
    {
        int read_write_ok = 1;
        sym_cipher_hdl_t *cipher_ctx;
        HMAC_CTX *hmac_ctx = HMAC_CTX_new();
        unsigned long file_curr_pos = 0;
        unsigned long file_hmac_pos = 0;
        unsigned long file_size = 0;
        unsigned long bytes_to_decrypt = 0;

	if (!hmac_ctx)
            stat = FAIL;

	if (SUCCESS == stat)
        {
        /*
         * Init symmetric cipher (they say that blowfish is fast so use it for now)
         * TODO take cipher as a parameter
         */
        stat = sym_cipher_init(&cipher_ctx, SYM_CIPHER_BLOWFISH, enc_key.k1, enc_key.key_size);
        HMAC_Init_ex(hmac_ctx, enc_key.k1, enc_key.key_size, EVP_sha1(), NULL);

        /*
         *  The file looks as follows:
         *  +---+-------...------+----+
         *  | R | cipher... text |HMAC|
         *  +---+-------...------+----+
         *  We are just after R now so have to get the current position of the file
         *  and go to the end to read the HMAC then go back and read and decrypt
         *  the file till get to place where HMAC sits and stop there
         */

        /* Get the current position */
        file_curr_pos = ftell(f_to_dec);
        /* Go to the end and get size of the file*/
        fseek(f_to_dec, 0, SEEK_END);
        file_size = ftell(f_to_dec);
        /* HMAC is at the end of the file - compute the offset to it */
        file_hmac_pos = file_size - SHA1_LEN;
        /* Go and read the HMAC*/
        fseek(f_to_dec, file_hmac_pos, SEEK_SET);
        dummy = fread(hmac_buff_from_file, 1, SHA1_LEN, f_to_dec);
        /* Go back and start from where we were */
        fseek(f_to_dec, file_curr_pos, SEEK_SET);
        /* will need to decrypt till we get to HMAC*/
        bytes_to_decrypt = file_hmac_pos - file_curr_pos;
        if (SUCCESS == stat)
        {
            char plain_txt_buff[SYM_CIPHER_DATA_UNIT_SIZE];
            char cipher_txt_buff[SYM_CIPHER_DATA_UNIT_SIZE];
            int read = 0;
            int written = 0;
            do
            {
                /*
                 * Get chunk of data from input file
                 */
                if (SYM_CIPHER_DATA_UNIT_SIZE < bytes_to_decrypt )
                    read = fread(cipher_txt_buff, 1, SYM_CIPHER_DATA_UNIT_SIZE, f_to_dec);
                else
                    read = fread(cipher_txt_buff, 1, bytes_to_decrypt, f_to_dec);
                if (read)
                {
                    /*
                     * decrypt it
                     */
                    if ((stat = sym_cipher_decrypt(cipher_ctx, (void*)cipher_txt_buff,
                                                      (void*)plain_txt_buff, read)) == SUCCESS)
                    {
                        /*
                         * Put it into output file
                         */
                        written = fwrite(plain_txt_buff, 1, read, f_dec);

                        /*
                         * Update Message Auth Code
                         */
                        HMAC_Update(hmac_ctx, (unsigned char*)cipher_txt_buff, read);

                        /*
                         * Check if everything that was read got written
                         */
                        if (read != written)
                        {
                            read_write_ok = 0;
                            stat = FAIL;
                        }
                    }
                    bytes_to_decrypt -= read;
                }
                /*
                 * Loop till get to the end of input file
                 * or something bad happen
                 */
            }
            while ((bytes_to_decrypt) && (! feof(f_to_dec)) && (read_write_ok) && (SUCCESS == stat));

            /*
             * If ok finalise HMAC computation and compare it from the HMAC from file
             * if it is equal that operation decrypt was successful
             * If not then something was wrong so print info and delete decrypted file
             */
            if (SUCCESS == stat)
            {
                HMAC_Final(hmac_ctx, hmac_buff, &hmac_len);
                fflush(f_dec);
                if (memcmp(hmac_buff, hmac_buff_from_file, SHA1_LEN) == 0)
                {
                    INFO_LOG("File decrypted successfully\n");
                }
                else
                {
                    INFO_LOG("File decryption failed. HMAC doesn't match\n");
                    stat = FAIL;
                }
            }
            /*
             * Clean the symmetric cipher session
             */
            sym_cipher_close(cipher_ctx);
            HMAC_CTX_free(hmac_ctx);
        }
        else
        {
            ERROR_LOG("Failed initialise symmectic cipher\n");
        }
        ec_release_enc_key(&enc_key);
        ec_release_key(&priv_key);
    }
    }
    else
    {
        ERROR_LOG("Failed to generate symmetric encryption key\n");
    }
    /*
     * Done. Do more cleanup and check the status.
     */
    fclose(f_to_dec);
    fclose(f_dec);
    if (SUCCESS != stat)
    {
        remove(dec_file_name);
    }
    return stat;
}
