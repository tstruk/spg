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

#ifndef _SPG_POINT_H_
#define _SPG_POINT_H_

typedef gcry_mpi_t big_number;

/*
 * EC Point Structue
 */ 
typedef struct EC_point_s
{
    big_number x;
    big_number y;
} EC_point_t;

/*
 * Will use domain parameters for Elliptic Curves over over prime Fp only.
 * Elliptic Curves over binary F2m is to be implemented 
 */ 
struct domain_GFp_params_s;
typedef struct domain_GFp_params_s GFp_params_t;

/*
 * Function: ec_point_is_infinity
 *
 */
int ec_point_is_infinity(const EC_point_t *p);

/*
 * Function: ec_point_init
 *
 */
void ec_point_init( EC_point_t *p );

/*
 * Function: ec_point_free
 *
 */
void ec_point_free( EC_point_t *p );

/*
 * Function: ec_point_zero
 *
 */
void ec_point_zero(EC_point_t *p);

/*
 * Function: ec_point_copy
 *
 */
void ec_point_copy(EC_point_t *p, const EC_point_t *q);

/*
 * Function: ec_point_on_curve
 *
 */
int ec_point_on_curve(const EC_point_t *p, const GFp_params_t *params);

/*
 * Function: ec_point_add
 *
 */
status ec_point_add( EC_point_t *r, const EC_point_t *q,
                     const EC_point_t *p, const GFp_params_t *params );

/*
 * Function: ec_point_double
 *
 */
status ec_point_double( EC_point_t *r, const EC_point_t *p,
                        const GFp_params_t *params );

/*
 * Function: ec_point_mulitply
 *
 */
EC_point_t ec_point_mulitply(const EC_point_t *p, const big_number d,
                             const GFp_params_t *params  );

/*
 * Function: ec_point_sub
 *
 */
status ec_point_sub( EC_point_t *r, const EC_point_t *q,
                     EC_point_t *p, const GFp_params_t *params );

/*
 * Function: ec_debug_print_point
 *
 */
void ec_debug_print_point(const EC_point_t const *p );

#endif
