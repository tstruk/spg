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
#include <gcrypt.h>
#include "defs.h"
#include "ec_point.h"
#include "ecc.h"
#include "utils.h"

/*
 * Point init 
 * Initializes the point to zero
 */ 
void ec_point_init( EC_point_t *p )
{
    p->x = gcry_mpi_new(0);
    p->y = gcry_mpi_new(0);
}

/*
 * Free point
 */ 
void ec_point_free( EC_point_t *p )
{
    gcry_mpi_release(p->x);
    gcry_mpi_release(p->y);
}

/*
 * Zero point
 */ 
void ec_point_zero(EC_point_t *p)
{
    gcry_mpi_set_ui(p->x, 0);
    gcry_mpi_set_ui(p->y, 0);
}

/*
 * Checks if the point is (0, 0)
 */ 
int ec_point_is_infinity(const EC_point_t *p)
{
    if ( ( gcry_mpi_cmp_ui(p->x, 0) == 0 ) && ( gcry_mpi_cmp_ui(p->y, 0) == 0 ) )
        return 1;
    return 0;
}

/*
 * Copy point q to p
 */ 
void ec_point_copy(EC_point_t *p, const EC_point_t *q)
{
    gcry_mpi_set(p->x, q->x);
    gcry_mpi_set(p->y, q->y);
}

/*
 * if y^2 == x^3+a*x+b then point is on the curve
 */
int ec_point_on_curve(const EC_point_t *p, const GFp_params_t *params)
{
    status res = SUCCESS;
    if ( ec_point_is_infinity(p) )
    {
        LOG( " Point is zero \n" );
        return FAIL;
    }
    else
    {
        gcry_mpi_t t1, t2;
        t1 = gcry_mpi_new(0);
        t2 = gcry_mpi_new(0);
        /* x^3 */
        gcry_mpi_mulm(t1, p->x, p->x, params->p);
        gcry_mpi_mulm(t1, t1, p->x, params->p);
        /*  x*a */
        gcry_mpi_mulm(t2, params->a, p->x, params->p);
        /* x^3 + x*a */
        gcry_mpi_addm(t1, t2, t1, params->p);
        /* x^3 + x*a + b */
        gcry_mpi_addm(t1, t1, params->b, params->p);
        /* y^2 */
        gcry_mpi_mulm(t2, p->y, p->y, params->p);
        res = gcry_mpi_cmp(t1, t2);
#ifdef DEBUG
        printf("ec_point_on_curve t1: \n");
        print_big_number(t1);
        printf("ec_point_on_curve t2: \n");
        print_big_number(t2);
#endif
        gcry_mpi_release(t1);
        gcry_mpi_release(t2);
    }
    return (!res);
}

/*
 * Point compare routine
 *
 */ 
int ec_point_cmp( const EC_point_t *p, const EC_point_t *q )
{
    if ( (gcry_mpi_cmp (p->x, q->x) == 0) && (gcry_mpi_cmp (p->y, q->y) == 0 ) )
        return 1;
    return 0;
}

/*
 * Point double routine see:
 * http://www.certicom.com/index.php/32-arithmetic-in-an-elliptic-curve-group-over-fp
 * 2P = R where
 * s = (3 * xP^2 + a) / (2 * yP ) mod p
 * xR = s^2 - 2xP mod p and yR = -yP + s(xP - xR) mod p
 */
status ec_point_double( EC_point_t *r, const EC_point_t *p, const GFp_params_t *params )
{
    gcry_mpi_t t1, t2, s;
    status stat = SUCCESS;

    if ( gcry_mpi_cmp_ui(p->y, 0) == 0 )
    {
        gcry_mpi_set_ui( r->x, 0 );
        return stat;
    }
    t1 = gcry_mpi_new(0);
    t2 = gcry_mpi_new(0);
    s = gcry_mpi_new(0);

    /* t1 = xp^2 */
    gcry_mpi_mulm(t1, p->x, p->x, params->p);

    /* t2 = 3* xp^2 */
    gcry_mpi_addm(t2, t1, t1, params->p);
    gcry_mpi_addm(t2, t2, t1, params->p);

    /* s = 3 * xp^2 + a */
    gcry_mpi_addm(s, t2, params->a, params->p);

    /* t2 = 2*yp */
    gcry_mpi_addm(t2, p->y, p->y, params->p);

    /* t2 = 1 / 2yp */
    gcry_mpi_invm( t2, t2, params->p );

    /* s = 3xp^2 + a / 2yp */
    gcry_mpi_mulm(s, s, t2, params->p);

    /* t1 = s ^ 2 */
    gcry_mpi_mulm(t1, s, s, params->p);

    /* t1 (xr) = s^2 - 2 * xp */
    gcry_mpi_subm(t1, t1, p->x, params->p);
    gcry_mpi_subm(t1, t1, p->x, params->p);

    /* t2 = xp - xr */
    gcry_mpi_subm( t2, p->x, t1, params->p);

    /* t2 = s * (xp - xr) */
    gcry_mpi_mulm(t2, s, t2, params->p);

    /* yr = -yp + s * (xp - xr) */
    gcry_mpi_subm(r->y, t2, p->y, params->p);
    /* xr = s^2 - 2 * xp*/
    gcry_mpi_set(r->x, t1);

    gcry_mpi_release(t1);
    gcry_mpi_release(t2);
    gcry_mpi_release(s);
    return stat;
}

/*
 * Point add routine see:
 * http://www.certicom.com/index.php/32-arithmetic-in-an-elliptic-curve-group-over-fp
 * P + Q = R where
 * s = (yP - yQ) / (xP - xQ) mod p
 * xR = s^2 - xP - xQ mod p and yR = -yP + s(xP - xR) mod p
 */
status ec_point_add( EC_point_t *r, const EC_point_t *p, const EC_point_t *q, const GFp_params_t *params )
{
    gcry_mpi_t t1, s;
    /* if q is 0 then r = p*/
    if ( ec_point_is_infinity(q) )
    {
        /* if r and p are not the same point */
        if ( r != p )
            ec_point_copy( r, p );
    }
    /* else if q is 0 then r = p*/
    else if ( ec_point_is_infinity(p) )
    {
        ec_point_copy( r, q );
    }
    /* else if p == q then r = 2p*/
    else if ( ec_point_cmp( p, q ) )
    {
        return ec_point_double( r, p, params );
    }
    else
    {
        t1 = gcry_mpi_new(0);
        s = gcry_mpi_new(0);

        /* t1 = yP - yQ*/
        gcry_mpi_subm(t1, p->y, q->y, params->p);
        /* r->y = ( xP - xQ ) */
        gcry_mpi_subm(r->y, p->x, q->x, params->p);
        /* r->y = 1/ r->y */
        gcry_mpi_invm(r->y, r->y, params->p);
        /* s = ( yP - yQ ) / ( xP - xQ ) */
        gcry_mpi_mulm(s, t1, r->y, params->p);
        /* t1 = s^2 */
        gcry_mpi_mulm(t1, s, s, params->p);
        /* r->x = s^2 - q->x */
        gcry_mpi_subm( r->x, t1, p->x, params->p );
        /* r->x = s^2 - q->x - p->x */
        gcry_mpi_subm( r->x, r->x, q->x, params->p );
        /* t1 = q->x - xR */
        gcry_mpi_subm(t1, q->x, r->x, params->p);
        /* r->y = s( xP - xR ) */
        gcry_mpi_mulm(r->y, s, t1, params->p);
        /* r->y = -yP + s( xP - xR ) */
        gcry_mpi_subm(r->y, r->y, q->y, params->p);

        /* free tmp variables */
        gcry_mpi_release(t1);
        gcry_mpi_release(s);
    }

    return SUCCESS;

}
/*
 * Point substruct
 */
status ec_point_sub( EC_point_t *r, const EC_point_t *q, EC_point_t *p, const GFp_params_t *params )
{
    gcry_mpi_t t1;
    t1 = gcry_mpi_new(0);
    gcry_mpi_set_ui(t1, 0);
    gcry_mpi_sub(p->y, t1, p->y);
    gcry_mpi_release(t1);
    return ec_point_add(r, q, p, params);
}

/*
 * Point multiply 
 */
EC_point_t ec_point_mulitply( const EC_point_t *p, const big_number d, const GFp_params_t *params  )
{
    int  i = 0;
    EC_point_t q, p_cpy;
    ec_point_init(&q);
    ec_point_init(&p_cpy);
    ec_point_copy( &p_cpy, p);

    for (i = 0 ; i < gcry_mpi_get_nbits( d ); i++)
    {
        if ( gcry_mpi_test_bit( d, i ) )
        {
            ec_point_add(&q, &q, &p_cpy, params);
        }
        ec_point_double( &p_cpy, &p_cpy, params );
    }
    if ( ! ec_point_on_curve(&q, params) )
    {
        ERROR_LOG("Point not on curve \n");
    }

    ec_point_free(&p_cpy);
    return q;
}

#define BUFF_SIZE 256
/*
 * Debug function - prints out the given point
 */
void ec_debug_print_point(const EC_point_t const *p)
{
    unsigned char buff[BUFF_SIZE] ;
    size_t buff_size = 0;
    memset(buff, '\0', BUFF_SIZE );
    printf("P.x:\n");
    gcry_mpi_print (GCRYMPI_FMT_HEX, buff, BUFF_SIZE ,&buff_size, p->x);
    printf("%s\nsize: %d\n", buff, (int) buff_size);
    memset(buff, '\0', BUFF_SIZE );
    printf("P.y:\n");
    gcry_mpi_print (GCRYMPI_FMT_HEX, buff, BUFF_SIZE ,&buff_size, p->y);
    printf("%s\nsize: %d\n", buff, (int) buff_size);
}
