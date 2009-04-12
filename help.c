/*************************************************************************
 * Small Privacy Guard
 * Copyright (C) Tadeusz Struk 2009 <tstruk@gmail.com>
 * $Id: $
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
#include "defs.h"

extern const char* program_name;

typedef struct help_s {
	char* opt_str;
	void (*help_funct)(void);
}help_t;

static void gen_key_help(void) 
{
	printf("\n SPG " VERSION_STRING "\n\n");
	printf("\nHelp for Generate Keys operation\n"  );
	printf("Generate Keys operation generates pair of keys - public and private \n"
		"based on an Eliptic Curve over prime.\n");
	printf("\nUse: %s -g [ -c<curve name> ] -o<output file>", program_name );
	printf("\nparameters:");
	printf("\n -c<curve name>  - Optional parameter. If ommited the default curve will be used");  
	printf("\n -o<output file> - File name where the private key will be stored" );
	printf("\nTo get all curves implemented use -l option.\n\n" );

}
static void export_key_help(void) 
{
	printf("\n SPG " VERSION_STRING "\n\n");
	printf("\nHelp for eXport Public Key operation \n"  );
	printf("eXport Public Key operation exports public from private key file \n"
		"passed in -k option to a new file passed in -o option\n");
	printf("\nUse: %s -x -k<private key> -o<public key>", program_name );
	printf("\nparameters:");
	printf("\n -k<private key> - Valid private key file generated with -g command");  
	printf("\n -o<public key>  - File name where the public key will be stored\n\n" );
}
 
static void sign_help(void) 
{
	printf("\n SPG " VERSION_STRING "\n\n");
	printf("\nHelp for Sign message operation\n"  );
	printf("\nUse: %s -s -k<private key> -o<signature file> message_file",program_name );
	printf("\nparameters:");
	printf("\n -k<private key>    - Valid private key file generated with -g command");  
	printf("\n -o<signature file> - File name where the signature will be stored" );
	printf("\n message_file       - Message file to sign\n\n" );

}

static void verify_help(void) 
{
	printf("\n SPG " VERSION_STRING "\n\n");
	printf("\nHelp for Verify Signature operation \n"  );
	printf("\nUse: %s -v -k<public key> -i<public key> message_file",program_name );
	printf("\nparameters:");
	printf("\n -k<public key>     - Valid public key exported from private key with -x command");  
	printf("\n -i<signature file> - File name where the signature is be stored" );
	printf("\n message_file       - Message file to which the signatures was generated\n\n" );	
}

static void encrypt_help(void) 
{
	printf("\n SPG " VERSION_STRING "\n\n");
	printf("\nHelp for encrypt operation.");
	printf("\nOperation will encrypt the <file_to_encrypt> file and the encrypted file will be \n"
		"stored with .enc suffix.\n" );
	printf("\nUse: %s -e -k<public key> file_to_encrypt",program_name );
	printf("\nparameters:");
	printf("\n -k<public key>     - Valid public key exported from private key with -x command");  
	printf("\n file_to_encrypt    - File to be encrypted\n\n" );		
}

static void decrypt_help(void) 
{
	printf("\n SPG " VERSION_STRING "\n\n");
	printf("\nHelp for decrypt operation \n"  );
	printf("\nUse: %s -d -k<private key> [-o<encrypted file>] file_to_decrypt",program_name );
	printf("\nparameters:");
	printf("\n -k<private key>    - Valid private key file generated with -g command");  
	printf("\n -o<encrypted file> - If the file_to_decrypt file has \".enc\" suffix then the parameter is optional.\n"
		 "                      If not the it has to be provided and the decrypted file will be stored in this file." );
	printf("\n file_to_decrypt    - File to be decrypted\n\n" );			
}


static help_t operations[ ] = {
	{ "gen_key", gen_key_help },
	{ "export", export_key_help }, 
	{ "sign", sign_help },
	{ "verify", verify_help },
	{ "encrypt", encrypt_help },
	{ "decrypt", decrypt_help },
	{ NULL, NULL }
	};

/*
 * General help
 */  
void print_help ( void )
{
	printf("\n SPG " VERSION_STRING "\n\n");
	printf("Use: %s commands [options] [file ...]\n", program_name );
	printf("Commands are: \n"
		"   -g --gen_key         Generate private key\n"
		"   -x --xport           eXport public key from private key\n"
		"   -s --sign            Generate message signature\n"
		"   -v --verify          Verify message signature\n"
		"   -e --encrypt         Encrypt\n"
		"   -d --decrypt         Decrypt\n"
		"   -l --list_curves     List implemented curves\n"
		"   -h --help            Print help and exit\n"
		);
	printf("Options are: \n"
		"   -c --curve           Use this curve\n"
		"   -i --input           Input file\n"
		"   -o --output          Output file\n"
		"   -V --verbose         Be loud\n"
		"   -t --timing          Print time spent computing ecc algorythms\n"
		);
	printf("\nFor more help on commands use: \n%s --help <command> \n", program_name );
	printf("\nE.g. \n%s --help sign\n\n", program_name );
}

void print_operation_help( const char* const opr )
{
	help_t *opr_ptr = operations;
	do {
		if( strncmp ( opr_ptr->opt_str, opr, strlen(opr_ptr->opt_str) ) == 0 )
		{
			opr_ptr->help_funct();
			return;
		}
		opr_ptr++;
	} while ( opr_ptr->opt_str );
	ERROR_LOG( "\"%s\" - no such command\n", opr  );
	print_help ( );
}


