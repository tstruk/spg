/*************************************************************************
 * Small Privacy Guard
 * Copyright (C) Tadeusz Struk 2009 <tstruk@gmail.com>
 * $Id: curves.c 272 2009-04-02 05:54:52Z tadeusz $
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
#include <assert.h>
#include <gcrypt.h>
#include "defs.h"
#include "ec_point.h"
#include "ecc.h"
#include "curves.h"

/*
 * All curves are defined based on secg recommended parameters in 
 * SEC 2: Recommended Elliptic Curve Domain Parameters doc
 * http://www.secg.org
 */ 
static curve_t curves_tab[] = {
/*
 * Curve secp112r1
 */
	{
		/* name */
		"secp112r1",
		/* oid */
		{ 1, 3, 132, 0, 6},
		/* curve params */
		/* prime p */
		"DB7C2ABF62E35E668076BEAD208B",
		/* a */
		"DB7C2ABF62E35E668076BEAD2088",
		/* b */
		"659EF8BA043916EEDE8911702B22",
		/* G (uncompressed)*/
		{
			/* x */
			"09487239995A5EE76B55F9C2F098",
			/* y */
			"A89CE5AF8724C0A23E0E0FF77500"
		},
		/* n */
		"DB7C2ABF62E35E7628DFAC6561C5",
		/* h */
		1
	},
/*
 * Curve secp112r2
 */
	{
		/* name */
		"secp112r2",
		/* oid */
		{1, 3, 132, 0, 7},
		/* curve params */
		/* prime p */
		"DB7C2ABF62E35E668076BEAD208B",
		/* a */
		"6127C24C05F38A0AAAF65C0EF02C",
		/* b */
		"51DEF1815DB5ED74FCC34C85D709",
		/* G (uncompressed)*/
		{
			/* x */
			"4BA30AB5E892B4E1649DD0928643",
			/* y */
			"ADCD46F5882E3747DEF36E956E97"
		},
		/* n */
		"36DF0AAFD8B8D7597CA10520D04B",
		/* h */
		4
	},
/*
 * Curve secp128r1
 */
	{
		/* name */
		"secp128r1",
		/* oid */
		{ 1, 3, 132, 0, 28},
		/* curve params */
		/* prime p */
		"FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF",
		/* a */
		"FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC",
		/* b */
		"E87579C11079F43DD824993C2CEE5ED3",
		/* G (uncompressed)*/
		{
			/* x */
			"161FF7528B899B2D0C28607CA52C5B86",
			/* y */
			"CF5AC8395BAFEB13C02DA292DDED7A83"
		},
		/* n */
		"FFFFFFFE0000000075A30D1B9038A115",
		/* h */
		1
	},
/*
 * Curve secp128r2
 */
	{
		/* name */
		"secp128r2",
		/* oid */
		{ 1, 3, 132, 0, 29},
		/* curve params */
		/* prime p */
		"FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF",
		/* a */
		"D6031998D1B3BBFEBF59CC9BBFF9AEE1",
		/* b */
		"5EEEFCA380D02919DC2C6558BB6D8A5D",
		/* G (uncompressed)*/
		{
			/* x */
			"7B6AA5D85E572983E6FB32A7CDEBC140",
			/* y */
			"27B6916A894D3AEE7106FE805FC34B44"
		},
		/* n */
		"3FFFFFFF7FFFFFFFBE0024720613B5A3",
		/* h */
		4
	},
/*
 * Curve secp160r1
 */
	{
		/* name */
		"secp160r1",
		/* oid */
		{ 1, 3, 132, 0, 8},
		/* curve params */
		/* prime p */
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF",
		/* a */
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC",
		/* b */
		"1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45",
		/* G (uncompressed)*/
		{
			/* x */
			"4A96B5688EF573284664698968C38BB913CBFC82",
			/* y */
			"23A628553168947D59DCC912042351377AC5FB32"
		},
		/* n */
		"0100000000000000000001F4C8F927AED3CA752257",
		/* h */
		1
	},
/*
 * Curve secp160r2
 */
	{
		/* name */
		"secp160r2",
		/* oid */
		{ 1, 3, 132, 0, 30},
		/* curve params */
		/* prime p */
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73",
		/* a */
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70",
		/* b */
		"B4E134D3FB59EB8BAB57274904664D5AF50388BA",
		/* G (uncompressed)*/
		{
			/* x */
			"52DCB034293A117E1F4FF11B30F7199D3144CE6D",
			/* y */
			"FEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E"
		},
		/* n */
		"0100000000000000000000351EE786A818F3A1A16B",
		/* h */
		1
	},

/*
 * Curve secp192r1
 */
	{
		/* name */
		"secp192r1",
		/* oid */
		{ 1, 3, 132, 0, 29},
		/* curve params */
		/* prime p */
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
		/* a */
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
		/* b */
		"64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
		/* G (uncompressed)*/
		{
			/* x */
			"188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
			/* y */
			"07192B95FFC8DA78631011ED6B24CDD573F977A11E794811"
		},
		/* n */
		"FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",
		/* h */
		1
	},
/*
 * Curve secp224r1
 */
	{
		/* name */
		"secp224r1",
		/* oid */
		{ 1, 3, 132, 0, 33},
		/* curve params */
		/* prime p */
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
		/* a */
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
		/* b */
		"B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
		/* G (uncompressed)*/
		{
			/* x */
			"B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
			/* y */
			"BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34"
		},
		/* n */
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
		/* h */
		1
	},
/*
 * Curve secp256r1
 */
	{
		/* name */
		"secp256r1",
		/* oid */
		{ 1, 3, 132, 0, 29},
		/* curve params */
		/* prime p */
		"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
		/* a */
		"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
		/* b */
		"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
		/* G (uncompressed)*/
		{
			/* x */
			"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
			/* y */
			"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
		},
		/* n */
		"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
		/* h */
		1
	},
/*
 * Curve secp384r1
 */
	{
		/* name */
		"secp384r1",
		/* oid */
		{ 1, 3, 132, 0, 29},
		/* curve params */
		/* prime p */
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
		/* a */
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
		/* b */
		"B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
		/* G (uncompressed)*/
		{
			/* x */
			"AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
			/* y */
			"3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"
		},
		/* n */
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
		/* h */
		1
	},
/*
 * Curve secp521r1
 */
	{
		/* name */
		"secp521r1",
		/* oid */
		{ 1, 3, 132, 0, 29},
		/* curve params */
		/* prime p */
		"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		/* a */
		"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
		/* b */
		"0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
		/* G (uncompressed)*/
		{
			/* x */
			"00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
			/* y */
			"011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"
		},
		/* n */
		"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
		/* h */
		1
	}
};


static inline unsigned int curves_number( void )
{
	return (sizeof(curves_tab) / sizeof(curve_t));
}

status populate_curve( curve* c ,curve_t* c_tab)
{
	status stat = SUCCESS;
	c->name = malloc(strlen( c_tab->name ) + 1); 
	memcpy ( c->name, c_tab->name, strlen( c_tab->name ) );
	c->name[strlen( c_tab->name )] = '\0';
	if( GPG_ERR_NO_ERROR != gcry_mpi_scan( &c->params.p , GCRYMPI_FMT_HEX, c_tab->p, 0, NULL) )
	{
		return FAIL;
	}
	if( GPG_ERR_NO_ERROR != gcry_mpi_scan( &c->params.a , GCRYMPI_FMT_HEX, c_tab->a, 0, NULL))
	{
		return FAIL;
	}
	if( GPG_ERR_NO_ERROR != gcry_mpi_scan( &c->params.b , GCRYMPI_FMT_HEX, c_tab->b, 0, NULL))
	{
		return FAIL;
	}
	if( GPG_ERR_NO_ERROR != gcry_mpi_scan( &c->params.G.x , GCRYMPI_FMT_HEX, c_tab->G.x, 0, NULL))
	{
		return FAIL;
	}
	if( GPG_ERR_NO_ERROR != gcry_mpi_scan( &c->params.G.y , GCRYMPI_FMT_HEX, c_tab->G.y, 0, NULL))
	{
		return FAIL;
	}
	if( GPG_ERR_NO_ERROR != gcry_mpi_scan( &c->params.n , GCRYMPI_FMT_HEX, c_tab->n, 0, NULL))
	{
		return FAIL;
	}
	c->params.h = c_tab->h;
	return stat;
}

void free_curve(curve *c)
{
	if( NULL != c->name )
	{
		free(c->name);
		c->name = NULL;
	}
	gcry_mpi_release( c->params.p);
	gcry_mpi_release( c->params.a );
	gcry_mpi_release( c->params.b );
	gcry_mpi_release( c->params.G.x );
	gcry_mpi_release( c->params.G.y );
	gcry_mpi_release( c->params.n );
	c->params.h = 0;
	return;
}

void init_curve( curve* c)
{
	memset(c, '\0', sizeof(curve));
}

status get_curve( curve* c, const char* name )
{
	int i = 0;
	status stat = FAIL;
	curve_t* c_tab = curves_tab;

	assert(c != NULL);
	init_curve(c);
	for(i = 0; i < curves_number(); i++ )
	{
		c_tab = &curves_tab[i];

		if( strncmp( name, c_tab->name, strlen(c_tab->name) ) == 0 )
		{
			if( (stat = populate_curve( c, c_tab) ) == FAIL )
			{
				free_curve(c);
			}
			break;
		}
	}
	return stat;
}

void list_curves( void )
{
	int i = 0;
	curve_t* c_tab = NULL;
	for(i = 0; i < curves_number(); i++ )
	{
		c_tab = &curves_tab[i];
		printf("%2d. %s \n", i+1, c_tab->name);
	}
}
