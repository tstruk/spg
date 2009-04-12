/*************************************************************************
 * Small Privacy Guard
 * Copyright (C) Tadeusz Struk 2009 <tstruk@gmail.com>
 * $Id: utils.c 272 2009-04-02 05:54:52Z tadeusz $
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

#define BUFF_SIZE 256

void print_big_number( big_number num )
{
	size_t buff_size = 0;
	unsigned char buff[BUFF_SIZE];
	memset (buff, '\0', BUFF_SIZE);
	gcry_mpi_print (GCRYMPI_FMT_HEX, buff, BUFF_SIZE, &buff_size, num);
	printf("Number: %s\nsize: %d\n", buff, (int) buff_size);
}

static int done = 0;

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

void inform_gather_random_data_done()
{
	done = 1;
	printf("done\n");
}

extern int timing;
void print_time(const struct timeval *before, const struct timeval *after)
{
	if( timing )
	{
		if( after->tv_sec == before->tv_sec )
		{
			printf("Operation time: %d.%06d s \n", 
				(unsigned int)(after->tv_sec - before->tv_sec), 
				(unsigned int)(after->tv_usec - before->tv_usec) 
				);
		}
		else
		{
			printf("Operation time: %d.%06d s \n", 
				(unsigned int)(after->tv_sec - before->tv_sec), 
				(unsigned int)( ( ( after->tv_sec - before->tv_sec ) * 1000000 )
					          + after->tv_usec - before->tv_usec) 
				);
		}
	}
}

