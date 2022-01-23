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

#ifndef _SPG_POINT_H_
#define _SPG_POINT_H_

typedef gcry_mpi_t big_number;

typedef struct EC_point_s
{
    big_number x;
    big_number y;
#ifdef JACOBIAN_COORDINATES
    big_number z;
#endif
} EC_point_t;

struct domain_GFp_params_s;
typedef struct domain_GFp_params_s GFp_params_t;

int ec_point_is_infinity_affine(const EC_point_t *p);
void ec_point_init(EC_point_t *p);
void ec_point_free(EC_point_t *p);
void ec_point_zero(EC_point_t *p);
void ec_point_copy(EC_point_t *p, const EC_point_t *q);
int ec_point_on_curve(const EC_point_t *p, const GFp_params_t *params);
status ec_point_add_affine(EC_point_t *r, const EC_point_t *q,
		           const EC_point_t *p, const GFp_params_t *params);
status ec_point_double_affine(EC_point_t *r, const EC_point_t *p,
                              const GFp_params_t *params);
EC_point_t ec_point_multiply(const EC_point_t *p, const big_number d,
                             const GFp_params_t *params );
status ec_point_sub(EC_point_t *r, const EC_point_t *q,
                    const EC_point_t *p, const GFp_params_t *params);
void ec_debug_print_point(const EC_point_t const *p);
#endif
