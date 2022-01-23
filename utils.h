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

#ifndef ECC_UTILS_H
#define ECC_UTILS_H

/*
 * Function shows a progress while waiting for /dev/random
 */
void inform_gather_random_data(void);

/*
 * Function informs user when done reading /dev/random
 */
void inform_gather_random_data_done(void);

/*
 * Debuging function - prints big number
 */
void print_big_number( big_number num );


#endif
