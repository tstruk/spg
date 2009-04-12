/*************************************************************************
 * Small Privacy Guard
 * Copyright (C) Tadeusz Struk 2009 <tstruk@gmail.com>
 * $Id: curves.h 272 2009-04-02 05:54:52Z tadeusz $
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

typedef struct point_str_s {
	char* x;
	char* y;
} point_t;

/*
 * Curve parameters in char* format
 * to be parsed into GFp_params_t format
 */ 
typedef struct curve_str_s {
	char* name;
	int oid[OID_NUMBERS];
	char* p;
	char* a;
	char* b;
	point_t G;
	char* n;
	int h;
} curve_t ;

status get_curve( curve* c, const char* name );
void free_curve(curve* c);
void list_curves( void );

#endif
