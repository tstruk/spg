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

#include <gcrypt.h>
#include <assert.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include "defs.h"
#include "ec_point.h"
#include "ecc.h"
#include "curves.h"
#include "utils.h"

/*
 * Structures used for time measurment
 */
static time_stamp_t ecc_time_before_op;
static time_stamp_t ecc_time_after_op;

/*
 *
 */
status ec_generate_key(EC_private_key_t* priv_key, const char *curve_name)
{
    curve c;
    status stat = SUCCESS;

    assert(priv_key != NULL);
    stat = get_curve_by_name(&c, curve_name);

    if ( SUCCESS != stat )
    {
        ERROR_LOG("Curve %s not found.\nCurrently implemented curves:\n", curve_name);
        list_curves();
        return FAIL;
    }
    priv_key->priv = mpi_new(0);
    /*
     * Public key = random big number d * G
     * Randomize priv key d
     */
    inform_gather_random_data();
    gcry_mpi_randomize ( priv_key->priv, mpi_get_nbits(c.params.n), GCRY_VERY_STRONG_RANDOM);
    inform_gather_random_data_done();
    get_time_stamp(&ecc_time_before_op);
    /*
     * Make sure d < n
     */
    mpi_mod( priv_key->priv, priv_key->priv, c.params.n);
    /*
     * Compute G * d
     */
    priv_key->pub.c = c;
    priv_key->pub.Q = ec_point_multiply( &c.params.G, priv_key->priv, &c.params );
    get_time_stamp(&ecc_time_after_op);
    print_time( &ecc_time_before_op, &ecc_time_after_op);
    return stat;
}

/*
 * TODO implement verify key
 */
status ec_verify_key( EC_private_key_t* priv_key )
{
    assert( priv_key != NULL );

    return SUCCESS;
}

/*
 *
 */
void ec_release_key(EC_private_key_t* priv_key)
{
    mpi_release(priv_key->priv);
    ec_point_free(&priv_key->pub.Q);
    free_curve(&priv_key->pub.c);
}

/*
 *
 */
void ec_release_public_key(EC_public_key_t* pub_key)
{
    ec_point_free(&pub_key->Q);
    free_curve(&pub_key->c);
}

/*
 *
 */
status ec_generate_signature( EC_private_key_t* priv_key, EC_signature_t* sign, void* data, size_t size )
{
    status stat = SUCCESS;
    gcry_md_hd_t hash;
    char* dgst = NULL;
    big_number k;
    big_number e;
    EC_point_t kG;
    int gen_s_ok = 1, gen_k_ok = 1;

    CHECK_PARAM( priv_key );
    CHECK_PARAM( sign );
    CHECK_PARAM( data );

    sign->r = mpi_new(0);
    sign->s = mpi_new(0);

    if ( gcry_md_open(&hash, GCRY_MD_SHA512, 0) != GPG_ERR_NO_ERROR )
    {
        ERROR_LOG("Init hash function failed\n");
        stat = FAIL;
    }
    gcry_md_write (hash, data, size);
    gcry_md_final(hash);
    dgst = (char*) gcry_md_read(hash, 0);

    do
    {
        gen_s_ok = 1;
        do
        {
            gen_k_ok = 1;
            /*
             * Generate random k
             */
            k = mpi_new(0);
            gcry_mpi_randomize ( k, mpi_get_nbits(priv_key->pub.c.params.n),
                                 GCRY_STRONG_RANDOM);
            get_time_stamp(&ecc_time_before_op);
            /*
             * Make sure k < n
             */
            mpi_mod( k, k, priv_key->pub.c.params.n);
            /*
             * compute kG = G * k
             */
            kG = ec_point_multiply( &priv_key->pub.c.params.G, k , &priv_key->pub.c.params );
            /*
             * r = kG.x
             */
            mpi_mod(sign->r, kG.x, priv_key->pub.c.params.n );
            ec_point_free(&kG);
            /*
             * if r != 0 then go farther
             */
            if ( mpi_cmp_ui(sign->r, 0) == 0 )
            {
                printf(" gen k not ok\n");
                gen_k_ok = 0;
                mpi_release(k);
            }
        }
        while (!gen_k_ok);
        gcry_mpi_scan(&e, GCRYMPI_FMT_USG, dgst, SHA512_LEN, NULL);
        /*
         * Make sure e < n
         */
        mpi_mod( e, e, priv_key->pub.c.params.n);
        /*
         * s = (e + (r * private_key) ) * 1/k
         */
        mpi_mulm(sign->s, priv_key->priv, sign->r, priv_key->pub.c.params.n);
        mpi_addm(sign->s, sign->s, e, priv_key->pub.c.params.n);
        mpi_invm(e, k, priv_key->pub.c.params.n);
        mpi_mulm(sign->s, sign->s, e, priv_key->pub.c.params.n);
        get_time_stamp(&ecc_time_after_op);
        /*
         * if s != 0 then pair of unmbers
         * s and r are the valid signature
         */
        if ( mpi_cmp_ui(sign->s, 0) == 0 )
        {
            gen_s_ok = 0;
            mpi_release(k);
            mpi_release(e);
        }
    }
    while (!gen_s_ok);

    print_time( &ecc_time_before_op, &ecc_time_after_op);
    mpi_release(k);
    mpi_release(e);
    gcry_md_close(hash);
    return stat;
}


/* TODO: add comments in the algorithm code
 * ec_verify_signature()
 * The algorithm is as follows:
 * 1. Verify that r and s are integers in [1,n - 1]. If not, the signature is invalid.
 * 2. Calculate e = HASH(m), where HASH is the same function used in the signature generation.
 * 3. Calculate w = 1/s (mod n).
 * 4. Calculate u1 = ew(mod n) and u2 = rw(mod n).
 * 5. Calculate (x1,y1) = u1 * G + u2 * QA.
 * The signature is valid if r = x1(mod n), invalid otherwise.
 */
status ec_verify_signature( EC_public_key_t* public_key, EC_signature_t* sign, void* data, size_t size )
{
    status stat = SUCCESS;
    CHECK_PARAM( public_key );
    CHECK_PARAM( sign );
    CHECK_PARAM( data );

    get_time_stamp(&ecc_time_before_op);
    /*
     * Check point 1:
     * 1. Verify that r and s are integers in [1,n - 1]. If not, the signature is invalid.
     */

    if ( mpi_cmp( sign->r, public_key->c.params.n ) > 0 )
    {
        LOG("Signature not valid - R is not in range from 0 to n-1\n");
        stat = FAIL;
    }
    if ( (stat == SUCCESS) &&
            ( ! ( mpi_cmp( sign->s, public_key->c.params.n ) < 0 ) ) )
    {
        LOG("Signature not valid - S is not in range from 0 to n-1\n");
        stat = FAIL;
    }

    if ( SUCCESS == stat )
    {
        char* dgst = NULL;
        gcry_md_hd_t hash;
        big_number w, e, u1, u2;

        EC_point_t u1G, u2QA, P;

        w  = mpi_new(0);
        u1 = mpi_new(0);
        u2 = mpi_new(0);
        ec_point_init( &P );

        if ( gcry_md_open(&hash, GCRY_MD_SHA512, 0) != GPG_ERR_NO_ERROR )
        {
            ERROR_LOG("Init hash function failed\n");
            stat = FAIL;
        }
        gcry_md_write (hash, data, size);
        gcry_md_final(hash);
        dgst = (char*) gcry_md_read(hash, 0);
        gcry_mpi_scan(&e, GCRYMPI_FMT_USG, dgst, SHA512_LEN, NULL);
        mpi_mod( e, e, public_key->c.params.n);

        mpi_invm(w, sign->s, public_key->c.params.n);
        mpi_mulm(u1, e, w, public_key->c.params.n );
        mpi_mulm(u2, sign->r, w, public_key->c.params.n );

        u1G = ec_point_multiply( &public_key->c.params.G, u1, &public_key->c.params  );
        u2QA = ec_point_multiply( &public_key->Q, u2, &public_key->c.params  );
        ec_point_add_affine(&u1G, &u1G, &u2QA, &public_key->c.params );
        
        get_time_stamp(&ecc_time_after_op);

        if ( mpi_cmp( sign->r, u1G.x ) == 0 )
        {
            LOG("Signature is valid\n");
        }
        else
        {
            ERROR_LOG("Signature is NOT valid\n");
            stat = SIGNATURE_INVALID;
        }
        print_time( &ecc_time_before_op, &ecc_time_after_op);
        gcry_md_close(hash);
        mpi_release( w );
        mpi_release( e );
        mpi_release( u1 );
        mpi_release( u2 );
        ec_point_free( &u1G );
        ec_point_free( &u2QA );
        ec_point_free( &P );
    }
    return stat;
}

/*
 *
 */
void ec_release_signature(EC_signature_t* signature )
{
    CHECK_PARAM( signature );
    mpi_release(signature->r);
    mpi_release(signature->s);
    return;
}

/*
 * ec_sym_key_derive - KDF (Key Derivation Function)
 */
#define BUFFER_SIZE ( 3 * MAX_BIG_NUM_SIZE )
static status ec_sym_key_derive(EC_enc_key_t* enc_key, big_number Zx)
{
    status stat = SUCCESS;
    unsigned char buff[BUFFER_SIZE];
    unsigned char *buff_ptr = buff;
    size_t len = 0;
    unsigned int space = 0;

    if (gcry_mpi_print(GCRYMPI_FMT_USG, buff_ptr,
                       BUFFER_SIZE - space, &len, enc_key->R.x ) == GPG_ERR_NO_ERROR )
    {
        buff_ptr += len;
        space += len;
        assert( BUFFER_SIZE > space );
    }
    else
    {
        ERROR_LOG("Filed to export data");
        stat = FAIL;
    }
    if ( ( SUCCESS == stat ) && ( gcry_mpi_print(GCRYMPI_FMT_USG, buff_ptr,
                                  BUFFER_SIZE - space, &len, enc_key->R.y ) == GPG_ERR_NO_ERROR ) )
    {
        buff_ptr += len;
        space += len;
        assert( BUFFER_SIZE > space );
    }
    else
    {
        ERROR_LOG("Filed to export data");
        stat = FAIL;
    }
    if ( ( SUCCESS == stat ) && ( gcry_mpi_print(GCRYMPI_FMT_USG, buff_ptr,
                                  BUFFER_SIZE - space, &len, Zx ) == GPG_ERR_NO_ERROR ) )
    {
        buff_ptr += len;
        space += len;
        assert( BUFFER_SIZE > space );
    }
    else
    {
        ERROR_LOG("Filed to export data");
        stat = FAIL;
    }
    if ( SUCCESS == stat)
    {
        gcry_md_hd_t hash;
        char* dgst = NULL;

        if ( gcry_md_open(&hash, GCRY_MD_SHA512, 0) != GPG_ERR_NO_ERROR )
        {
            ERROR_LOG("Init hash function failed\n");
            stat = FAIL;
        }
        gcry_md_write (hash, buff, space);
        gcry_md_final(hash);
        dgst = (char*) gcry_md_read(hash, 0);
        enc_key->k1 = malloc( SHA512_LEN );
        memcpy( enc_key->k1 , dgst, SHA512_LEN );
        enc_key->k2 = enc_key->k1 + ( SHA512_LEN / 2 );
        enc_key->key_size = SHA512_LEN / 2;
        gcry_md_close(hash);
    }
    return stat;
}

/*
 *
 */
status ec_generate_enc_key( EC_enc_key_t* enc_key, EC_public_key_t* public_key )
{
    status stat = SUCCESS;
    big_number k, h;
    EC_point_t Z;
    int gen_k_ok = 1;

    CHECK_PARAM( enc_key );
    CHECK_PARAM( public_key );
    get_time_stamp(&ecc_time_before_op);

    do
    {
        gen_k_ok = 1;
        k = mpi_new(0);
        h = mpi_set_ui( NULL, public_key->c.params.h );
        /*
         * Generate random k
         */
        gcry_mpi_randomize ( k, mpi_get_nbits(public_key->c.params.n),
                             GCRY_STRONG_RANDOM);
        /*
         * Make sure k < n
         */
        mpi_mod( k, k, public_key->c.params.n);

        /*
         * enc_key.R = k * G
         */
        enc_key->R = ec_point_multiply( &public_key->c.params.G, k, &public_key->c.params );

        mpi_mul_ui( k, k, public_key->c.params.h );

        Z = ec_point_multiply( &public_key->Q, k, &public_key->c.params );


        /*
         * if Z == 0 the generate k again
         */
        if ( ec_point_is_infinity_affine( &Z ) )
        {
            gen_k_ok = 0;
            mpi_release( k );
            mpi_release( h );
            ec_point_free( &Z );
            ec_point_free( &enc_key->R );
        }

    }
    while (!gen_k_ok);

    /*
     * Derive symmetric keys for cipher and HMAC
     */
    stat = ec_sym_key_derive( enc_key, Z.x );
    get_time_stamp(&ecc_time_after_op);
    print_time( &ecc_time_before_op, &ecc_time_after_op);

    mpi_release( k );
    mpi_release( h );
    ec_point_free( &Z );

    return stat;
}

/*
 *
 */
status ec_generate_dec_key( EC_enc_key_t* enc_key, EC_private_key_t* priv_key )
{
    status stat = SUCCESS;
    EC_point_t Z;
    big_number hd;

    CHECK_PARAM( enc_key );
    CHECK_PARAM( priv_key );

    hd = mpi_new(0);
    get_time_stamp(&ecc_time_before_op);

    mpi_mul_ui(hd, priv_key->priv, priv_key->pub.c.params.h );
    Z = ec_point_multiply( &enc_key->R , hd, &priv_key->pub.c.params );

    if ( ec_point_is_infinity_affine( &Z ) )
    {
        ec_point_free( &Z );
        mpi_release( hd );
        return FAIL;
    }

    stat = ec_sym_key_derive( enc_key, Z.x );
    get_time_stamp(&ecc_time_after_op);
    print_time( &ecc_time_before_op, &ecc_time_after_op);
    mpi_release( hd );
    ec_point_free( &Z );
    return stat;
}

/*
 *
 */
void ec_release_enc_key(EC_enc_key_t* enc_key)
{
    CHECK_PARAM( enc_key );
    ec_point_free( &enc_key->R );
    FREE( enc_key->k1 );
}

