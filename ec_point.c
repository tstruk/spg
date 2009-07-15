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
/*
 * Some the algorithms in this file are described in details in 
 * "Guide to Elliptic Curve Cryptography" book by D. Hankerson,
 * A. Menezes and S. Vanstone. If a function implements an algorithm
 * described in this book there is a reference in the function 
 * description pointing to the book. Some of the algorithms, as noted 
 * in a function description are also described by Certicom 
 * at http://www.certicom.com/index.php
 */ 

#include <stdio.h>
#include <gcrypt.h>
#include <math.h>
#include "defs.h"
#include "ec_point.h"
#include "ecc.h"
#include "utils.h"
#include "curves.h"


#ifdef JACOBIAN_COORDINATES
#define EC_POINT_DOUBLE_OPT ec_point_double_jacobian
#define EC_POINT_ADD_OPT ec_point_add_jacobian
#else
#define EC_POINT_DOUBLE_OPT ec_point_double_affine
#define EC_POINT_ADD_OPT ec_point_add_affine
#endif

#define VALIDATE_POINT
#define mpi_print gcry_mpi_print

void ec_point_init( EC_point_t *p )
{
    p->x = mpi_new(0);
    p->y = mpi_new(0);
#ifdef JACOBIAN_COORDINATES
    p->z = mpi_new(0);
#endif
}

void ec_point_free( EC_point_t *p )
{
    mpi_release(p->x);
    mpi_release(p->y);
#ifdef JACOBIAN_COORDINATES 
    mpi_release(p->z);
#endif
}

void ec_point_zero(EC_point_t *p)
{
    mpi_set_ui(p->x, 0);
    mpi_set_ui(p->y, 0);
#ifdef JACOBIAN_COORDINATES 
    mpi_set_ui(p->z, 0);
#endif
}

int ec_point_is_infinity_affine(const EC_point_t *p)
{
    if ( ( mpi_cmp_ui(p->x, 0) == 0 ) 
                   && ( mpi_cmp_ui(p->y, 0) == 0 ) )
    {
        return 1;
    }
    return 0;
}


void ec_point_copy(EC_point_t *p, const EC_point_t *q)
{
    mpi_set(p->x, q->x);
    mpi_set(p->y, q->y);
#ifdef JACOBIAN_COORDINATES 
    mpi_set(p->z, q->z);
#endif
}


int ec_point_cmp( const EC_point_t *p, const EC_point_t *q )
{
    if ( (mpi_cmp (p->x, q->x) == 0) 
            && (mpi_cmp (p->y, q->y) == 0 ) 
#ifdef JACOBIAN_COORDINATES 
            && (mpi_cmp (p->z, q->z) == 0 )
#endif  
            )
    {
        return 1;
    }
    return 0;
}


/*********************************************** 
 * Function definitions for affine coordinates 
 ***********************************************/
/*
 * Point double using affine coordinates. Reference:
 * http://www.certicom.com/index.php/32-arithmetic-in-an-elliptic-curve-group-over-fp
 * 2P = R where
 * s = (3 * xP^2 + a) / (2 * yP ) mod p
 * xR = s^2 - 2xP mod p and yR = -yP + s(xP - xR) mod p
 */
status ec_point_double_affine( EC_point_t *r, const EC_point_t *p, const GFp_params_t *params )
{
    big_number t1, t2, s;
    status stat = SUCCESS;

    if ( mpi_cmp_ui(p->y, 0) == 0 )
    {
        mpi_set_ui( r->x, 0 );
        return stat;
    }
    t1 = mpi_new(0);
    t2 = mpi_new(0);
    s = mpi_new(0);

    /* t1 = xp^2 */
    mpi_mulm(t1, p->x, p->x, params->p);

    /* t2 = 3* xp^2 */
    mpi_addm(t2, t1, t1, params->p);
    mpi_addm(t2, t2, t1, params->p);

    /* s = 3 * xp^2 + a */
    mpi_addm(s, t2, params->a, params->p);

    /* t2 = 2*yp */
    mpi_addm(t2, p->y, p->y, params->p);

    /* t2 = 1 / 2yp */
    mpi_invm( t2, t2, params->p );

    /* s = 3xp^2 + a / 2yp */
    mpi_mulm(s, s, t2, params->p);

    /* t1 = s ^ 2 */
    mpi_mulm(t1, s, s, params->p);

    /* t1 (xr) = s^2 - 2 * xp */
    mpi_subm(t1, t1, p->x, params->p);
    mpi_subm(t1, t1, p->x, params->p);

    /* t2 = xp - xr */
    mpi_subm( t2, p->x, t1, params->p);

    /* t2 = s * (xp - xr) */
    mpi_mulm(t2, s, t2, params->p);

    /* yr = -yp + s * (xp - xr) */
    mpi_subm(r->y, t2, p->y, params->p);
    /* xr = s^2 - 2 * xp*/
    mpi_set(r->x, t1);

    mpi_release(t1);
    mpi_release(t2);
    mpi_release(s);
    return stat;
}

/*
 * Point add using affine coordinates. Reference:
 * http://www.certicom.com/index.php/32-arithmetic-in-an-elliptic-curve-group-over-fp
 * P + Q = R where
 * s = (yP - yQ) / (xP - xQ) mod p
 * xR = s^2 - xP - xQ mod p and yR = -yP + s(xP - xR) mod p
 */
status ec_point_add_affine( EC_point_t *r, const EC_point_t *p, const EC_point_t *q, const GFp_params_t *params )
{
    big_number t1, s;
    /* if q is 0 then r = p*/
    if ( ec_point_is_infinity_affine(q) )
    {
        /* if r and p are not the same point */
        if ( r != p )
            ec_point_copy( r, p );
    }
    /* else if q is 0 then r = p*/
    else if ( ec_point_is_infinity_affine(p) )
    {
        ec_point_copy( r, q );
    }
    /* else if p == q then r = 2p*/
    else if ( ec_point_cmp( p, q ) )
    {
        return ec_point_double_affine( r, p, params );
    }
    else
    {
        t1 = mpi_new(0);
        s = mpi_new(0);

        /* t1 = yP - yQ*/
        mpi_subm(t1, p->y, q->y, params->p);
        /* r->y = ( xP - xQ ) */
        mpi_subm(r->y, p->x, q->x, params->p);
        /* r->y = 1/ r->y */
        mpi_invm(r->y, r->y, params->p);
        /* s = ( yP - yQ ) / ( xP - xQ ) */
        mpi_mulm(s, t1, r->y, params->p);
        /* t1 = s^2 */
        mpi_mulm(t1, s, s, params->p);
        /* r->x = s^2 - q->x */
        mpi_subm( r->x, t1, p->x, params->p );
        /* r->x = s^2 - q->x - p->x */
        mpi_subm( r->x, r->x, q->x, params->p );
        /* t1 = q->x - xR */
        mpi_subm(t1, q->x, r->x, params->p);
        /* r->y = s( xP - xR ) */
        mpi_mulm(r->y, s, t1, params->p);
        /* r->y = -yP + s( xP - xR ) */
        mpi_subm(r->y, r->y, q->y, params->p);

        /* free tmp variables */
        mpi_release(t1);
        mpi_release(s);
    }
    return SUCCESS;
}


#ifdef JACOBIAN_COORDINATES
/*********************************************** 
 * Function definitions for jacobian coordinates 
 ***********************************************/

/*
 * Check if jacobian point is infinity
 */ 
static int ec_point_is_infinity_jacobian(const EC_point_t *p)
{
    if ( mpi_cmp_ui(p->z, 0) == 0 )
    {
        return 1;
    }
    return 0;
}

/*
 * Point double routine using jacobian coordinates
 * Formula 3.13 in "Guide to Elliptic Curve Cryptography"
 * NOTE: The algorithm was takken from paper 
 * "A practical implementation of elliptic curve cryptosystems over
 * GF (p) on a 16-bit microcomputer." by Toshio Hasegawa, 
 * Junko Nakajima, and Mitsuru Matsui with my modification to steps
 * 15, 16, 17 & 18 to avoid expensive division as noted in the code.
 *
 * The algorithm goes as follows
 * S = 4*X*Y^2
 * M = 3*X^2 + a*Z^4
 * X' = M^2 - 2*S
 * Y' = M*(S - X') - 8*Y^4
 * Z' = 2*Y*Z
 * return (X', Y', Z')
 */ 

status ec_point_double_jacobian( EC_point_t *r, const EC_point_t *p, const GFp_params_t *params )
{
  
    status stat = SUCCESS;
    big_number t1, t2;

    if( ec_point_is_infinity_jacobian(p) )
    {
        return stat;
    }
    t1 = mpi_new(0);
    t2 = mpi_new(0);

    mpi_mulm(t1, p->z, p->z, params->p);
    mpi_mulm(p->z, p->y, p->z, params->p);
    mpi_addm(p->z, p->z, p->z, params->p);

    mpi_mulm(t1, t1, t1, params->p);
    mpi_mulm(t1, params->a, t1, params->p);
    mpi_mulm(t2, p->x, p->x, params->p);
    mpi_addm(t1, t2, t1, params->p);
    mpi_addm(t2, t2, t2, params->p);
    mpi_addm(t1, t2, t1, params->p);

#if 0
    /* instead of doing expensive division 
     * to calculate 8y^4*/
    {
    big_number two;
    two = mpi_new(0);
    mpi_set_ui(two, 2);
    mpi_addm(p->y, p->y, p->y, params->p);
    mpi_mulm(p->y, p->y, p->y, params->p);
    mpi_mulm(t2, p->y, p->y, params->p);
    mpi_mulm(p->y, p->y, p->x, params->p);
    mpi_invm(two, two, params->p);
    mpi_mulm(t2, t2, two, params->p);
    mpi_release(two);
    }
#else
    /* lets do it like this - works much faster */
    /* y = y^2 */
    mpi_mulm(p->y, p->y, p->y, params->p);
    /* y = 2y^2 */
    mpi_addm(p->y, p->y, p->y, params->p);
    /* t2 = 4y^4 */
    mpi_mulm(t2, p->y, p->y, params->p);
    /* t2 = 8y^4 */ 
    mpi_addm(t2, t2, t2, params->p);
    /* y = 4y^2 */
    mpi_addm(p->y, p->y, p->y, params->p);
    /* y = 4y^2 * x */
    mpi_mulm(p->y, p->y, p->x, params->p);
#endif    
    mpi_mulm(p->x, t1, t1, params->p);
    mpi_subm(p->x, p->x, p->y, params->p);
    mpi_subm(p->x, p->x, p->y, params->p);
    mpi_subm(p->y, p->y, p->x, params->p);
    mpi_mulm(p->y, p->y, t1, params->p);
    mpi_subm(p->y, p->y, t2, params->p);
    mpi_release(t1);
    mpi_release(t2);
    return stat;
}

/* 
 *  U1 = X1*Z2^2
 *  T1 = X2*Z1^2
 *  S1 = Y1*Z2^3
 *  T2 = Y2*Z1^3
 *  if (X1 == U2)
 *    if (Y1 != S2)
 *      return POINT_AT_INFINITY
 *    else 
 *      return POINT_DOUBLE(X1, Y1, Z1)
 *  H = U2 - U1
 *  R = S2 - S1
 *  X3 = R^2 - H^3 - 2*U1*H^2
 *  Y3 = R*(U1*H^2 - X3) - S1*H^3
 *  Z3 = H*Z1*Z2
 *  return (X3, Y3, Z3)
 */ 
status ec_point_add_jacobian( EC_point_t *r, const EC_point_t *p, const EC_point_t *q, const GFp_params_t *params )
{
    status stat = SUCCESS;
    big_number u1, u2, s1, s2, H, R;

    if ( ec_point_is_infinity_jacobian(q) )
    {
        if ( r != p )
        {
            ec_point_copy( r, p );
        }
        return stat;
    }
    if ( ec_point_is_infinity_jacobian(p) )
    {
        ec_point_copy( r, q );
        mpi_set_ui( r->z, 1 );
        return stat;
    }
    u1 = mpi_new(0);
    u2 = mpi_new(0);
    s1 = mpi_new(0);
    s2 = mpi_new(0);

    mpi_mulm(u1, q->z, q->z, params->p); /* u1 = z2^2 */
    mpi_mulm(s1, u1, q->z, params->p);   /* s1 = z2^3 */
    mpi_mulm(u1, u1, p->x, params->p);   /* u1 = x1 * z2^2 */
    mpi_mulm(u2, p->z, p->z, params->p); /* u2 = z1^2 */
    mpi_mulm(s2, u2, p->z, params->p);   /* s1 = z1^3 */
    mpi_mulm(u2, u2, q->x, params->p);   /* u2 = x2 * z1^2 */
    mpi_mulm(s1, s1, p->y, params->p);   /* s1 = y1 * z2^3 */
    mpi_mulm(s2, s2, q->y, params->p);   /* s2 = y2 * z1^3 */

    if(mpi_cmp( u1, u2 ) == 0 )
    {
        mpi_release(u1);
        mpi_release(u2);
        if( mpi_cmp(s1,s2) == 0)
        {
            mpi_release(s1);
            mpi_release(s2);
            mpi_set_ui( q->z, 1 );  
            return ec_point_double_jacobian( r, p, params );
        }
        else
        {
            mpi_set_ui( r->x, 1 );  
            mpi_set_ui( r->y, 1 );  
            mpi_set_ui( r->z, 0 );  
            return stat;   
        }
    }
    H = mpi_new(0);
    R = mpi_new(0);

    mpi_subm(H, u2, u1, params->p);  /* H = u2 - u1 */
    mpi_subm(R, s2, s1, params->p);  /* R = s2 - s1 */

    mpi_mulm(r->x, R, R, params->p); /* x3 = R^2 */
    mpi_mulm(u2, H, H, params->p);   /* u2 = H^2 */
    mpi_mulm(s2, u2, H, params->p);  /* u2 = H^3 */

    mpi_subm(r->x, r->x, s2, params->p); /* x3 = R^2 - H^3 */
    mpi_addm(r->y, u1, u1, params->p);   /* y3 = 2u1 */
    mpi_mulm(r->y, r->y, u2, params->p);   /* y3 = 2u1 * H^2 */
    mpi_subm(r->x, r->x, r->y, params->p); /* x3 = R^2 - H^3 - 2u1* H^2 */
   
    mpi_mulm(s1, s1, s2, params->p);   /* s1 = s1 * H^3 */
    mpi_mulm(r->y, u1, u2, params->p);   /* y3 = u1 * H^2 */
    mpi_subm(r->y, r->y, r->x, params->p);  /* y3 = u1 * H^2 - x3 */
    mpi_mulm(r->y, r->y, R, params->p);  /* y3 = R(u1 * H^2 - x3) */
    mpi_subm(r->y, r->y, s1, params->p);  /* y3 = R(u1 * H^2 - x3) - s1*H^3 */
    
    mpi_mulm(r->z, p->z, q->z, params->p); /* z3 = z1 * z2 */
    mpi_mulm(r->z, r->z, H, params->p);    /* z3 = z1 * z2 * H */

    mpi_release(u1);
    mpi_release(u2);
    mpi_release(s1);
    mpi_release(s2);
    mpi_release(H); 
    mpi_release(R);
    return stat;
}


/* 
 * Jacobian to affine point  
 * JP=(JP.X, JP.Y, JP.Z) --> P=( x=JP.X/JP.Z^2, y=JP.Y/JP.Z^3 ) 
 */
void ec_point_jacobian_to_affine( EC_point_t *r, const EC_point_t *p,
                                    const GFp_params_t *params )
{
    if (!ec_point_is_infinity_jacobian(p)) 
    {
        big_number t1, t2;
        t1 = mpi_new(0);
        t2 = mpi_new(0);
        /* t1 = 1/z */
        mpi_invm(t1, p->z, params->p);
        /* t1 = 1/z^2 */
        mpi_mulm(t2, t1, t1, params->p);
        /* p.x = jp.x * 1/z^2 */
        mpi_mulm(r->x, p->x, t2, params->p);
        /* t1 = 1/z^3 */
        mpi_mulm(t1, t1, t2, params->p);
        /* p.y = jp.y * 1/z^3 */
        mpi_mulm(r->y, p->y, t1, params->p);
        mpi_set_ui(r->z, 1);
        mpi_release(t1);
        mpi_release(t2);
    }

}

#endif /* JACOBIAN_COORDINATES */

/*
 * Point substruct
 * The inverse of P = (x,y(,z)) is -P = (x,-y(,z))
 * So need to change the sign of Py and add R = Q + P
 */
status ec_point_sub( EC_point_t *r, const EC_point_t *q, const EC_point_t *p, const GFp_params_t *params )
{
    status stat = SUCCESS;
    big_number tmp;
    EC_point_t tmpp;
    ec_point_init(&tmpp);
    tmp = mpi_new(0);
    mpi_set_ui(tmp, 0);
    mpi_sub(tmpp.y, tmp, p->y);
    mpi_set(tmpp.x, p->x);
#ifdef JACOBIAN_COORDINATES
    mpi_set(tmpp.z, p->z);
#endif
    mpi_release(tmp);
    stat = EC_POINT_ADD_OPT(r, q, &tmpp, params);
    ec_point_free(&tmpp);
    return stat;
}

/*
 * Check if the point in on the curve. It is 
 * if y^2 == x^3+a*x+b
 */
int ec_point_on_curve(const EC_point_t *p, const GFp_params_t *params)
{
    int res = 0;
    if ( ec_point_is_infinity_affine(p) )
    {
        LOG( " Point is zero \n" );
        return res;
    }
    else
    {
        big_number t1, t2;
        t1 = mpi_new(0);
        t2 = mpi_new(0);
        /* x^3 */
        mpi_mulm(t1, p->x, p->x, params->p);
        mpi_mulm(t1, t1, p->x, params->p);
        /*  x*a */
        mpi_mulm(t2, params->a, p->x, params->p);
        /* x^3 + x*a */
        mpi_addm(t1, t2, t1, params->p);
        /* x^3 + x*a + b */
        mpi_addm(t1, t1, params->b, params->p);
        /* y^2 */
        mpi_mulm(t2, p->y, p->y, params->p);
        res = ( mpi_cmp(t1, t2) == 0 ) ? 1 : 0;
#ifdef DEBUG
        printf("ec_point_on_curve t1: \n");
        print_big_number(t1);
        printf("ec_point_on_curve t2: \n");
        print_big_number(t2);
#endif
        mpi_release(t1);
        mpi_release(t2);
    }
    return res;
}

#ifdef LEFT_TO_RIGH_MULT
/*
 * Point multiply
 * Implementation of Left-to-right Binary method
 * Algorithm 3.27 in Guide to ECC
 */
EC_point_t ec_point_multiply( const EC_point_t *p, const big_number d, const GFp_params_t *params  )
{
    EC_point_t q;
    ec_point_init(&q);
    int i = 0;
    for( i = mpi_get_nbits(d)-1; i>=0 ; i-- )
    {
         EC_POINT_DOUBLE_OPT( &q, &q, params );
         if (mpi_test_bit(d, i))
         {
             EC_POINT_ADD_OPT( &q, &q, p, params);
         }
    }
#ifdef JACOBIAN_COORDINATES    
    ec_point_jacobian_to_affine( &q, &q, params);
#endif      

#ifdef VALIDATE_POINT    
    if ( ! ec_point_on_curve(&q, params) )
    {
        ERROR_LOG("Point not on curve \n");
    }
#endif    
    return q;
}

#endif /* RIGH_TO_LEFT_MULT */

#ifdef BINARY_NAF_MULT
/*
 * NAF precomputes for max keylen + 1 
 */ 
static int8_t NAF[MAX_KEY_LEN+1];

/*
 * Point multiply
 * Implementation of Binary NAF method
 * Algorithms 3.30 & 3.31 in Guide to ECC
 */
EC_point_t ec_point_multiply( const EC_point_t *p, const big_number d, const GFp_params_t *params  )
{
    int i = 0, l = 0, ret = 0;
    int8_t naf_ki = 0;
    size_t size = 1;
    EC_point_t q;
    big_number two, four, k, r, ki;
    
    ec_point_init(&q);
    k = mpi_new(0);
    r = mpi_new(0);
    ki = mpi_new(0);
    two = mpi_new(0);
    four = mpi_new(0);
    mpi_set_ui(two, 2); 
    mpi_set_ui(four, 4); 
    mpi_set(k, d);

    /* Calculate NAF */
    while( mpi_cmp_ui (k, 0) > 0 )
    {
        mpi_tdiv (ki, r, k, two);
        if( mpi_cmp_ui (r, 0) == 0)
        {
            NAF[l] = 0;
        }
        else
        {
            naf_ki = 0;
            mpi_mod(ki, k, four);
            mpi_sub(ki, two, ki);
            ret = mpi_print(GCRYMPI_FMT_USG,
                       (unsigned char*)&naf_ki, size, &size ,ki);
            if(ret)
            {
                  ERROR_LOG("mpi print failed %d\n", ret);
            }
            ret = mpi_cmp_ui( ki, 0 );

            if ( ret > 0 )
            {
                NAF[l] = naf_ki;
            }
            else
            {
                NAF[l] = naf_ki * -1;
            }
            mpi_sub(k, k, ki);
        }
        mpi_tdiv (k, r, k, two);
        l++;
    }

    for (i = l-1 ; i >= 0 ; i--)
    {
        EC_POINT_DOUBLE_OPT( &q, &q, params );
        if (  NAF[i] == 1 )
        {
            EC_POINT_ADD_OPT(&q, &q, p, params);
        }
        else if (  NAF[i] == -1 )
        {
            ec_point_sub(&q, &q, p, params);
        }
    }

    mpi_release(k);
    mpi_release(r);
    mpi_release(ki);
    mpi_release(two);
    mpi_release(four);
#ifdef JACOBIAN_COORDINATES    
    ec_point_jacobian_to_affine(&q, &q, params);
#endif  
#ifdef VALIDATE_POINT    
    if ( ! ec_point_on_curve(&q, params) )
    {
        ERROR_LOG("Point not on curve \n");
    }
#endif    
    return q;
}
#endif /* BINARY_NAF_MULT */

#ifdef WINDOW_NAF_MULT
/*
 * NAF precomputes for max keylen + 1 
 */ 
static int8_t wNAF[MAX_KEY_LEN + 1];

#define MAX_WINDOW_SIZE 6
#define MAX_PRECOMPUTES 31 /* (2 to power of (MAX_WINDOW_SIZE-1))-1 */
#define MAX_PRECOMPUTES_TAB 15 /* odd numbers only ( MAX_PRECOMPUTES ) / 2  */

static EC_point_t precomputes[MAX_PRECOMPUTES_TAB];

static inline size_t get_window_size( size_t bits )
{
    if(bits > 256) 
            return 4;
    return 3;
}

/*
 * Point multiply
 * Implementation of window NAF method
 * Algorithms 3.35 & 3.36 in Guide to ECC
 */
EC_point_t ec_point_multiply( const EC_point_t *p, const big_number d, const GFp_params_t *params  )
{
    int i = 0, x = 0, l = 0, ret = 0, window_size = 0, 
        bits = 0, tpw = 0, sign = 1;
    int8_t wnaf_ki = 0;
    size_t size = 1;
    EC_point_t q;
    big_number two, k, r, ki, mod;
    
    ec_point_init(&q);
    k = mpi_new(0);
    r = mpi_new(0);
    ki = mpi_new(0);
    two = mpi_new(0);
    mod = mpi_new(0);
    mpi_set_ui(two, 2); 
    mpi_set(k, d);

    bits = mpi_get_nbits( d );
    window_size = get_window_size(bits);
    tpw = pow(2, window_size);

    mpi_set_ui(mod, tpw);

    /* Calculate NAF */
    while( mpi_cmp_ui (k, 0) > 0 )
    {
        mpi_tdiv (ki, r, k, two);
        if( mpi_cmp_ui (r, 0) == 0)
        {
            wNAF[l] = 0;
        }
        /* 
         * k mods 2w is a signed integer representation of the 'window_size' rightmost bits.
         * Need to mask out all but the 'window_size' rightmost w bits and don't forget the sign 
         */
        else
        {
            wnaf_ki = 0;
            mpi_set(ki, k);
            mpi_clear_highbit( ki, window_size + 1 );
            /* if let MSB is set it will become a sign - the number is negative */
            if( mpi_test_bit ( ki, window_size ) )
            {
                big_number tmp;
                tmp = mpi_new(0);
                sign = -1;
                mpi_clear_bit ( ki, window_size);
                /* and just make the ki negative as well */
                mpi_set(tmp, ki);
                mpi_sub( ki, ki, tmp );
                mpi_sub( ki, ki, tmp );
            }
            else
            {
                sign = 1;
            }
            ret = mpi_print(GCRYMPI_FMT_USG,
                      (unsigned char*) &wnaf_ki, size, &size ,ki);
            if(ret)
            {
                  ERROR_LOG("mpi print failed %d\n", ret);
            }

            wNAF[l] = wnaf_ki * sign;
            mpi_sub(k, k, ki);
        }
        mpi_tdiv (k, r, k, two);
        l++;
    }
    /* calculate precomputes */
    for(i = 1; i < tpw; i++ )
    {
        if(i % 2)
        {
            ec_point_init(&precomputes[i]);
            for(x = 0; x < i; x++)
            {
                EC_POINT_ADD_OPT(&precomputes[i], &precomputes[i], p, params);
#ifdef JACOBIAN_COORDINATES
                ec_point_jacobian_to_affine(&precomputes[i], &precomputes[i], params);
#endif                
            }
        }
    }

    /* precomputes done now do multiply using precomputes */
    for (i = l-1 ; i >= 0 ; i--)
    {
        EC_POINT_DOUBLE_OPT( &q, &q, params );
        if (  wNAF[i] != 0 )
        {
            if( wNAF[i] > 0 )
            {
                EC_POINT_ADD_OPT(&q, &q, &precomputes[wNAF[i]], params);
            }
            else
            {
                ec_point_sub(&q, &q, &precomputes[wNAF[i] * -1 ], params);
            }
        }
    }
    /* free precomputes */
    for(i = 1; i < tpw; i++ )
    {
        if(i % 2)
        {
            ec_point_free(&precomputes[i]);
        }
    }
    mpi_release(k);
    mpi_release(r);
    mpi_release(ki);
    mpi_release(two);
    mpi_release(mod);
#ifdef JACOBIAN_COORDINATES 
    ec_point_jacobian_to_affine(&q, &q, params);
#endif  
#ifdef VALIDATE_POINT
    if ( ! ec_point_on_curve(&q, params) )
    {
        ERROR_LOG("Point not on curve \n");
    }
#endif    
    return q;
}
#endif /* WINDOW_NAF_MULT */

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
    mpi_print (GCRYMPI_FMT_HEX, buff, BUFF_SIZE ,&buff_size, p->x);
    printf("%s\nsize: %d\n", buff, (int) buff_size);
    memset(buff, '\0', BUFF_SIZE );
    printf("P.y:\n");
    mpi_print (GCRYMPI_FMT_HEX, buff, BUFF_SIZE ,&buff_size, p->y);
    printf("%s\nsize: %d\n", buff, (int) buff_size);
#ifdef JACOBIAN_COORDINATES 
    printf("P.z:\n");
    mpi_print (GCRYMPI_FMT_HEX, buff, BUFF_SIZE ,&buff_size, p->z);
    printf("%s\nsize: %d\n", buff, (int) buff_size);
#endif    
}
