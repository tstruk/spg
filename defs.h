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

#ifndef _SPG_DEFS_H_
#define _SPG_DEFS_H_

#define VERSION_MAJOR "0"
#define VERSION_MINOR "4"
#define VERSION_REV   "8"

#define VERSION_STRING VERSION_MAJOR "." VERSION_MINOR "." VERSION_REV

extern const char* program_name;
extern int verbose;
extern int timing;

typedef enum
{
    SUCCESS = 0,
    FAIL,
    BAD_PARAMS,
    SIGNATURE_INVALID,
    ENCRYPTION_FAILED,
    DECRYPTION_FAILED,
    NOT_IMPLEMENTED
} status;

#define ERROR_LOG( mesg, params... )                                \
	do {                                                            \
	printf( "ERROR: %s:%d - "  mesg, __FILE__, __LINE__, ##params );\
	} while(0)


#define DEBUG_LOG( mesg, params... )                                \
	do {                                                            \
	printf( "DEBUG: %s:%d - "  mesg, __FILE__, __LINE__, ##params );\
	} while(0)

#define INFO_LOG( mesg, params... )     \
	do {                                \
	printf( "INFO: "  mesg, ##params ); \
	} while(0)

#define LOG( mesg, params... )                    \
	do {                                          \
		if( verbose )                             \
			printf( "MESSAGE: " mesg, ##params ); \
	} while(0)

#define CHECK_PARAM( param )                                      \
	do {                                                          \
		if( param == NULL )                                       \
		{                                                         \
			ERROR_LOG("Invalid parameter: \"%s\" passed to funct" \
				  " \"%s\"\n", #param, __FUNCTION__ );            \
			assert( param != NULL );                              \
		}                                                         \
	} while(0)

#define FREE( data )  \
do {                  \
	if( data )        \
	{                 \
		free(data);   \
		data = NULL;  \
	}                 \
} while(0)


#define PEM_PUB_KEY_NAME "SPG PUBLIC KEY"
#define PEM_PRV_KEY_NAME "SPG PRIVATE KEY"
#define PEM_SIGN_NAME    "SPG SIGNATURE"
#define PEM_EMPTY_STR    ""

#define SHA1_LEN 20
#define SHA512_LEN 64
#define MAX_MSG_SIZE 0x40000 /*256K Bytes*/
#define MAX_MSG_SIZE_STR "256K Bytes"
#define MAX_BIG_NUM_SIZE 134 /* Max size of the big number in bytes. For curve secp521r1 it is 133 */
#define MAX_FILE_NAME_SIZE 256
#define SYM_CIPHER_DATA_UNIT_SIZE 1024
#define ENCRYPTED_FILE_SUFFIX ".enc"

#endif /* _SPG_DEFS_H_ */
