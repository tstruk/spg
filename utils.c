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
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <gcrypt.h>
#include "defs.h"
#include "ec_point.h"
#include "utils.h"

#define BUFF_SIZE 256

/*
 * Globals
 */
const char* program_name = "spg";
int verbose = 0;

/*
 * Debuging function - prints big number
 */
void print_big_number( big_number num )
{
    size_t buff_size = 0;
    unsigned char buff[BUFF_SIZE];
    memset (buff, '\0', BUFF_SIZE);
    gcry_mpi_print (GCRYMPI_FMT_HEX, buff, BUFF_SIZE, &buff_size, num);
    printf("Number: %s\nsize: %d\n", buff, (int) buff_size);
}

static int done = 0;

/*
 *
 */
static void* inform ( void* param)
{
    printf("working");
    while (!(done))
    {
        printf(".");
        fflush( stdout );
        sleep(1);
    }
    pthread_exit(NULL);
}

/*
 * Function shows a progress while waiting for /dev/random
 */
void inform_gather_random_data()
{
    pthread_t thread;
    int res = 0 ;
    done = 0;
    printf("Going to gather random data. It can take a few seconds.\n");
    printf("It is recommended that you perform some other work e.g."
           " move mouse and type in on keyboard.\n");
    res = pthread_create( &thread, NULL,  inform , NULL);
}

/*
 * Function informs user when done reading /dev/random
 */
void inform_gather_random_data_done()
{
    done = 1;
    printf("\ndone\n");
}
