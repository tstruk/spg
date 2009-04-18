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

#ifndef _SPG_ECC_H_
#define _SPG_ECC_H_

typedef enum security_level_e {
	key56 = 56,
	key64 = 64,
	key80 = 80,
	key96 = 96,
	key112 = 112,
	key128 = 128,
	key160 = 160,
	key192 = 192,
	key224 = 224,
	key256 = 256,
	key384 = 384,
	key521 = 521
} security_level_t;

/*
 * ECC domain parameters
 * over prime number
 */ 
struct domain_GFp_params_s {
	/*
	 * Prime number p
	 */ 
	big_number p;
	/*
	 * Equation parameters y^2 = x^3 + a*x + b
	 * where a and b need to meet the following 
	 * constrain: 4*a^3 + 27*b != 0 
	 */ 
	big_number a;
	big_number b;
	/*
	 * Base point G = (xg, yg) on the curve
	 */ 
	EC_point_t G;
	/*
	 * Order of G 
	 */ 
	big_number n;
	/*
	 * cofactor h = #E(Fp)/n
	 */ 
	unsigned int h;
};

typedef struct curve_over_GFp_s {
	char* name;
	/*
	 * Curve Object ID (OID)
	 * For example see http://www.oid-info.com/get/1.3.132.0.6
	 */  
	char* oid;
	security_level_t security;
	GFp_params_t params;
} GFp_curve_t;

/*
 * Currently  will only use 
 * curver over prime
 */ 
typedef GFp_curve_t curve;

/*
 * Public key structure
 */ 
typedef struct EC_public_key_s {
	EC_point_t Q;
	curve c;
} EC_public_key_t;

/*
 * Private key structure
 */ 
typedef struct EC_private_key_s {
	EC_public_key_t pub;
	big_number priv;
} EC_private_key_t;

/*
 * Message signature structure
 */  
typedef struct EC_signature_s {
	big_number r; 
	big_number s;
} EC_signature_t;

/*
 * Message signature structure
 */  
typedef struct EC_enc_key_s {
	EC_point_t R;
	char* k1; /* key for symmetric cipher */
	char* k2; /* key for MAC */
	size_t key_size;
} EC_enc_key_t;

/*
 * Function: ec_generate_key()
 * Generates pair of keys - public and private over a curve 
 */ 
status ec_generate_key(EC_private_key_t* priv_key, const char *curve);

/*
 * Function: ec_verify_key()
 * Verify the given key
 */ 
status ec_verify_key( EC_private_key_t* priv_key );

/*
 * Function: ec_release_key()
 * Releases the pair of keys
 */ 
void ec_release_key(EC_private_key_t* priv_key);

/*
 * Function: ec_release_public_key()
 * Releases the public key
 */ 
void ec_release_public_key(EC_public_key_t* pub_key);

/*
 * Function: ec_generate_signature()
 * Generates signature using ECDSA algorithm
 */ 
status ec_generate_signature( EC_private_key_t* priv_key, EC_signature_t* sign, void* data, size_t size );

/*
 * Function: ec_verify_signature()
 * Verifies signature using ECDSA algorithm
 */ 
status ec_verify_signature( EC_public_key_t* public_key, EC_signature_t* sign, void* data, size_t size );

/*
 * Function: ec_release_signature()
 * Releases signature 
 */ 
void ec_release_signature( EC_signature_t* sign );

/*
 * Function: ec_generate_enc_key()
 * 
 */ 
status ec_generate_enc_key( EC_enc_key_t* enc_key, EC_public_key_t* public_key );

/*
 * Function: ec_generate_dec_key()
 * 
 */ 
status ec_generate_dec_key( EC_enc_key_t* enc_key, EC_private_key_t* priv_key );

/*
 * Function: ec_release_enc_key()
 * Frees memory allocated for encription key
 */ 
void ec_release_enc_key(EC_enc_key_t* enc_key);

#endif
