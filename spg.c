/*************************************************************************
 * Small Privacy Guard
 * Copyright (C) Tadeusz Struk 2009 <tstruk@gmail.com>
 * $Id$
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
#include <string.h>
#include <getopt.h>
#include <sys/stat.h>
#include <gcrypt.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <assert.h>

#include "spg.h"

/*
 * File private variables
 */

typedef enum
{
    op_noop = 0,
    op_gen_key,
    op_exp_pub_key,
    op_gen_sign,
    op_ver_sign,
    op_encrypt,
    op_decrypt,
    op_help

} operation;

typedef struct operation_params_s
{
    char* curve_name;
    char* input;
    char* output;
    char* key_file;
    char* arg;
    sym_cipher cipher;
} operation_params_t;

static status do_operation( operation op, operation_params_t* params )
{
    status stat = SUCCESS;
    switch ( op )
    {
    case op_gen_key:
        /*
         * Operation generate ECC keys
         */
        stat = generate_keys( params->curve_name, params->output );
        if (stat != SUCCESS)
        {
            INFO_LOG( "Generate keys operation failed\n");
        }
        else
        {
            LOG("Generated privte key and stored it in %s file\n", params->output );
        }

        break;
    case op_exp_pub_key:
        /*
         * Operation export ECC public key
         */
        stat = export_public_key( params->key_file, params->output );
        if (stat != SUCCESS)
        {
            INFO_LOG( "Export public key operation failed\n");
        }
        else
        {
            LOG("Exported public key and stored it in %s file\n", params->output );
        }
        break;
    case op_gen_sign:
        /*
         * Operation generate message signature
         */
        stat = generate_signature( params->key_file, params->output, params->arg );
        if (stat != SUCCESS)
        {
            INFO_LOG( "Generate message signature operation failed\n");
        }
        else
        {
            INFO_LOG("Signature generated successfully\n");
        }

        break;
    case op_ver_sign:
        /*
         * Operation verify message signature
         */
        stat = verify_signature( params->key_file, params->input, params->arg );
        if (stat == SUCCESS)
        {
            INFO_LOG("Signature is valid\n");
        }
        else if ( stat == SIGNATURE_INVALID )
        {
            INFO_LOG("Signature is NOT valid\n");
        }
        else
        {
            ERROR_LOG("Signature verify failed\n");
        }
        break;
    case op_encrypt:
        /*
         * Operation Encrypt
         */
        stat = encrypt( params->key_file, params->arg, params->cipher);
        if (stat != SUCCESS)
        {
            ERROR_LOG( "Encrypt operation failed\n");
        }
        break;
    case op_decrypt:
        /*
         * Operation Decrypt
         */
        stat = decrypt( params->key_file, params->arg, params->output, params->cipher );
        if (stat != SUCCESS)
        {
            ERROR_LOG( "Decrypt operation failed\n");
        }
        break;
    case op_help:
        /*
         * Operation print help
         */
        print_operation_help(params->arg);
        break;
    default:
        print_help();
        stat = FAIL;
        break;
    }

    return stat;
}

int main(int argc, char** argv)
{
    status stat = SUCCESS;
    int next_option = 0;
    const char* const default_curve = "secp160r2";
    const char* const default_priv_key = "spg_priv.key";
    const char* const default_pub_key = "spg_pub.key";
    const char* const default_signature = "spg.sign";

    operation opr = op_noop;
    operation_params_t params;
    memset( &params, '\0', sizeof(params));
    params.cipher = SYM_CIPHER_BLOWFISH;

    /*
     * Possible user params are
     */
    const char* const short_options = "gxsvedlphc:i:k:o:Vt";
    const struct option long_options [] =
    {
        /* Operations */
        { "gen_key", 0, NULL, 'g' },     /* Generate private key  */
        { "xport", 0, NULL, 'x' },       /* Export public key from private key */
        { "sign", 0, NULL, 's' },        /* Generate message signature */
        { "verify", 0, NULL, 'v' },      /* Verify message signature */
        { "encrypt", 0, NULL, 'e' },     /* Encrypt data */
        { "decrypt", 0, NULL, 'd' },     /* Decrypt data */
        { "list_curves", 0, NULL, 'l' }, /* Lits implemented curves */
        { "list_sym_ciphers", 0, NULL, 'p' }, /* Lits symmetric ciphers */
        { "help", 0, NULL, 'h' },        /* Print help and exit */
        /* Options */
        { "verbose", 0, NULL, 'V' },     /* Turn verbose on */
        { "curve", 1, NULL, 'c' },       /* Choose curve */
        { "input", 1, NULL, 'i' },       /* Input file */
        { "key", 1, NULL, 'k' },         /* Private/Public Key file */
        { "output", 1, NULL, 'o' },      /* Output file */
        { "timing", 0, NULL, 't' },      /* Print timing */
        { NULL, 0, NULL, 0 }             /* NULL terminator*/
    };

    program_name = argv[0];
    /*
     * Process user params
     */
    do
    {
        next_option = getopt_long(argc, argv, short_options, long_options, NULL );
        switch (next_option)
        {
        case 'g':
            opr = op_gen_key;
            break;
        case 'x':
            opr = op_exp_pub_key;
            break;
        case 's':
            opr = op_gen_sign;
            break;
        case 'v':
            opr = op_ver_sign;
            break;
        case 'e':
            opr = op_encrypt;
            break;
        case 'd':
            opr = op_decrypt;
            break;
        case 'l':
            list_curves();
            exit(SUCCESS);
        case 'p':
            sym_cipher_list();
            exit(SUCCESS);
        case 'h':
            opr = op_help;
            break;
        case 'c':
            params.curve_name = optarg;
            break;
        case 'i':
            params.input = optarg;
            break;
        case 'k':
            params.key_file = optarg;
            break;
        case 'o':
            params.output = optarg;
            break;
        case 'V':
            verbose = 1;
            break;
        case 't':
            timing = 1;
            break;
        case -1:
            break;
        case '?':
            print_help();
        default:
            exit(FAIL);
        }
    }
    while ( next_option != -1 );

    /*
     * Validate params
     */
    if (!params.curve_name)
        params.curve_name = (char*) default_curve;
    switch ( opr )
    {
    case op_gen_key:

        if ( NULL == params.output )
        {
            INFO_LOG("Using default file name for the "
                     "private key: %s\n", default_priv_key );
            params.output = (char*)default_priv_key;
        }
        break;
    case op_exp_pub_key:

        if ( NULL == params.key_file )
        {
            INFO_LOG("Looking for the private key in the "
                     "default location: %s\n", default_priv_key );
            params.key_file = (char*)default_priv_key;
        }
        if ( NULL == params.output )
        {
            INFO_LOG("Using default file name for the "
                     "public key: %s\n", default_pub_key );
            params.output = (char*)default_pub_key;
        }
        break;
    case op_gen_sign:

        params.arg = argv[optind];
        if ( NULL != params.arg )
        {
            if ( NULL == params.key_file )
            {
                INFO_LOG("Looking for the private key in the "
                         "default location: %s\n", default_priv_key );
                params.key_file = (char*)default_priv_key;
            }
            if ( NULL == params.output )
            {
                INFO_LOG("Signature file will be stored under the "
                         "default file name: %s\n", default_priv_key );
                params.output = (char*)default_signature;
            }
        }
        else
        {
            INFO_LOG("No file to sign. Try --help\n");
            stat = BAD_PARAMS;
        }
        break;
    case op_ver_sign:

        params.arg = argv[optind];
        if ( NULL != params.arg )
        {
            if ( NULL == params.key_file)
            {
                INFO_LOG("No key file provided. Try --help\n");
                stat = BAD_PARAMS;

            }
            if ( NULL == params.input )
            {
                INFO_LOG("No signature file provided. Try --help\n");
                stat = BAD_PARAMS;
            }
        }
        else
        {
            INFO_LOG("No file to verify. Try --help\n");
            stat = BAD_PARAMS;
        }

        break;
    case op_encrypt:

        params.arg = argv[optind];
        if ( NULL != params.arg )
        {
            if (NULL == params.key_file)
            {
                INFO_LOG("No key file provided. Try --help\n");
                stat = BAD_PARAMS;
            }
        }
        else
        {
            INFO_LOG("No file to encrypt. Try --help\n");
            stat = BAD_PARAMS;
        }
        break;
    case op_decrypt:

        params.arg = argv[optind];
        if ( NULL != params.arg )
        {
            if ( NULL == params.key_file )
            {
                INFO_LOG("Looking for the private key in the "
                         "default location: %s\n", default_priv_key );
                params.key_file = (char*)default_priv_key;
            }
        }
        else
        {
            INFO_LOG("No file to decrypt. Try --help\n");
            stat = BAD_PARAMS;
        }

        break;
    case op_help:

        params.arg = argv[optind];
        if ( NULL == params.arg )
        {
            print_help();
            stat = BAD_PARAMS;
        }
        break;
    default:
        break;
    }

    /*
     * Now call do operation and pass the params
     */
    if ( SUCCESS == stat )
        stat = do_operation( opr, &params );
    return stat;
}
