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
#ifndef _SPG_HELP_H_
#define _SPG_HELP_H_

/*
 * Prints general help
 */ 
void print_help ( void );

/*
 * Prints help on given command
 */ 
void print_operation_help( const char* const opr );

#endif /* _SPG_HELP_H_ */
