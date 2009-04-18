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

#ifndef SPG_SYM_CIPHER
#define SPG_SYM_CIPHER

/*
 * List of supported symmetric ciphers  
 */ 
typedef enum {
	
	SYM_CIPHER_BLOWFISH = 0,
	SYM_CIPHER_AES,
	SYM_CIPHER_TERM
} sym_cipher;
extern const char* cipher_names[];

/*
 * Symmetric cipher context
 */ 
typedef struct sym_cipher_hdl_s {
	
	status (*encrypt) ( struct sym_cipher_hdl_s*, void*, void*, size_t);
	status (*decrypt) ( struct sym_cipher_hdl_s*, void*, void*, size_t);
	status (*uninit) ( struct sym_cipher_hdl_s* );
	void* ctx; /* cipher private context */
	
} sym_cipher_hdl_t;

/*
 * Function: sym_cipher_init
 * Initialises symmetric cipher context. Curently only supported ciphers 
 * are indicated by sym_cipher  enum
 */ 
inline status sym_cipher_init( sym_cipher_hdl_t** cipher_hdl, sym_cipher cipher, void* key, size_t key_len );

/*
 * Function: sym_cipher_encrypt
 * Encrypt data using symmetric cipher
 */ 
inline status sym_cipher_encrypt( sym_cipher_hdl_t* cipher_hdl, void* in, void* out, size_t len );

/*
 * Function: sym_cipher_decrypt
 * Decrypt data using symmetric cipher
 */ 
inline status sym_cipher_decrypt( sym_cipher_hdl_t* cipher_hdl, void* in, void* out, size_t len );

/*
 * Function: sym_cipher_close
 * Release symmetric cipher context
 */ 
inline status sym_cipher_close( sym_cipher_hdl_t* cipher_hdl );

/*
 * Function: list_ciphers
 */ 
void sym_cipher_list(void);

#endif /* SPG_SYM_CIPHER */

