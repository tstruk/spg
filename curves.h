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

#ifndef _SPG_CURVES_H_
#define _SPG_CURVES_H_

#define MAX_KEY_LEN 521

typedef struct point_str_s
{
    char* x;
    char* y;
} point_t;

/*
 * Curve parameters in char* format
 * to be parsed into GFp_params_t format
 */
typedef struct curve_str_s
{
    char* name;
    security_level_t security;
    char* oid;
    char* p;
    char* a;
    char* b;
    point_t G;
    char* n;
    int h;
} curve_t ;

/*
 * Function: get_curve_by_name
 * Returns curve structure that coresponds to the curve name
 * To list all curves names use list_curves
 */
status get_curve_by_name(curve* c, const char* name);

/*
 * Function: get_curve_by_key_len
 * Returns curve structure where the prime p is min len
 * bits long
 */
status get_curve_by_key_len(curve* c, const int len);

/*
 * Function: free_curve
 * Free all memory fo the curve structure
 */
void free_curve(curve* c);

/*
 * Function: list_curves
 * Lists all implemented curves
 */
void list_curves(void);

#endif
