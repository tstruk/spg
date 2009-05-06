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
int timing = 0;

/*
 * Function reads and returns time stamp register on x86 architecutres
 * On other architectures returns zero.
 */
static inline unsigned long long rdtsc(void)
{
    /* Works only for x86 */
#if defined(__i386__) || defined(__x86_64__)
    unsigned int a, d;
__asm__ volatile("rdtsc" : "=a" (a), "=d" (d));
    return ((unsigned long long)a) | (((unsigned long long)d) << 32);;
#else
    return 0;
#endif
}

/*
 *
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
 *
 */
void inform_gather_random_data()
{
    pthread_t thread;
    int res = 0 ;
    done = 0;
    printf("Going to gather random data. It can take a few seconds.\n");
    printf("It is recomended that you perform some other work e.g."
           " move mouse and type in on keyboard.\n");
    res = pthread_create( &thread, NULL,  inform , NULL);
}

/*
 *
 */
void inform_gather_random_data_done()
{
    done = 1;
    printf("\ndone\n");
}

/*
 *
 */
void get_time_stamp( time_stamp_t* time )
{
    if ( timing )
    {
        memset(time, '\0', sizeof(time_stamp_t));
        time->cycles = rdtsc();
        clock_gettime(CLOCK_REALTIME, &time->time_v );
    }
}

/*
 *
 */
void print_time(const time_stamp_t *before, const time_stamp_t *after)
{
    if ( timing )
    {
        if ( after->time_v.tv_sec == before->time_v.tv_sec )
        {
            printf("Operation time: 0.%06d sec in %llu  CPU cycles\n",
                   (unsigned int)((after->time_v.tv_nsec - before->time_v.tv_nsec) / 1000 ),
                   after->cycles - before->cycles
                  );
        }
        else
        {
            if ( before->time_v.tv_sec < after->time_v.tv_nsec  )
            {
                printf("Operation time: %d.%06d sec in %llu CPU cycles.\n",
                       (unsigned int)(after->time_v.tv_sec - before->time_v.tv_sec),
                       (unsigned int)(after->time_v.tv_nsec - before->time_v.tv_nsec) / 1000 ,
                       after->cycles - before->cycles
                      );
            }
            else
            {
                printf("Operation time: %d.%06d sec in %llu CPU cycles.\n",
                       (unsigned int)(after->time_v.tv_sec - before->time_v.tv_sec) - 1,
                       (unsigned int)(1000000000 - (before->time_v.tv_nsec - after->time_v.tv_nsec)) / 1000 ,
                       after->cycles - before->cycles
                      );
            }
        }
    }
}

