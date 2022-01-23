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
#ifndef _SPG_OPS_H_
#define _SPG_OPS_H_
/*
 * generate_key
 * Generates private key on curve curve_name
 * and writes the key to file out_file in PEM format
 */
status generate_keys(char* curve_name, char* out_file);

/*
 * Function: export_public_key
 * Exports public key from the private key stored in in_file
 * and writes it to out_file
 */
status export_public_key(char* in_file, char* out_file);
status generate_signature(char* input, char* output, char* message);
status verify_signature(char* input, char* output, char* message);
status encrypt(char* key_file, char* file_to_encrypt, sym_cipher cipher);
status decrypt(char* key_file, char* file_to_decrypt, char* output, sym_cipher cipher);
#endif
