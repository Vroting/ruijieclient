/*******************************************************************************\
 * RuijieClient -- a CLI based Ruijie Client authentication modified from mystar *
 *                                                                               *
 * Copyright (C)  microcai(microcai@sina.com)                                    *
 \*******************************************************************************/

/*
 * parse.c
 *
 *      Author: microcai
 *
 * Parse the command line arguments, and read form config file
 * (if not overrided by command line argument )*
 *
 */

/*****************************************************/

#include "prase.h"

static inline int stob( char*s )
{
	if ( strncmp( s, "yes", 3 ) )
		return 0;
	else
		return 1;
}
void ParseParameters(int * argc, char ** argv[], struct parameter_tags p_[])
{
	long i = 0;

	struct parameter_tags *p;
	while (i < *argc)
	{
		p = p_;
		while (p->parameter)
		{
			if (!strncmp((*argv)[i], p->prefix, p->prefix_len))
			{
				switch (p->type)
				{
				case STUB:
					break;
				case BOOL_long:
				case BOOL_both:
					if ((*argv)[i][p->prefix_len] == '=')
					{
						*(int*) p->parameter = stob((*argv)[i]
								+ p->prefix_len + 1);
						(*argv)[i] = 0;
						break;
					}
					else if ((*argv)[i][p->prefix_len] == 0)
					{
						if ((*argv)[i + 1][0] != '-')
						{
							(*argv)[i] = 0;
							*(int*) p->parameter = stob((*argv)[++i]);
							(*argv)[i] = 0;
						}
						else
						{
							*(int*) p->parameter = 1;
							(*argv)[i] = 0;
						}
						break;
					}
					if (p->type == BOOL_long)
						break;
				case BOOL_short:
					*(int*) p->parameter = 1;
					if ((*argv)[i][1] != '-')
					{
						strcat((*argv)[i] + 1, (*argv)[i] + 2);
						--i;
					}else (*argv)[i]=0;
					break;
				case INTEGER:
					if ((*argv)[i][p->prefix_len] == 0)
					{
						(*argv)[i]=0;
						++i;
						if (p->parameter_len == sizeof(long))
							*(long*) p->parameter = atol((*argv)[i]);
						else if (p->parameter_len == sizeof(long))
							*(int*) p->parameter = atoi((*argv)[i]);
						else
							exit(0);
					}
					else if((*argv)[i][p->prefix_len] == '=')
					{
						if (p->parameter_len == sizeof(long))
							*(long*) p->parameter = atol((*argv)[i]+p->prefix_len+1);
						else if (p->parameter_len == sizeof(long))
							*(int*) p->parameter = atoi((*argv)[i]+p->prefix_len+1);
						else
							exit(0);
					}
					(*argv)[i]=0;
					break;
				case STRING:
					if ((*argv)[i][p->prefix_len] == 0)
					{
						(*argv)[i++] = 0;
						strncpy((char*) p->parameter, (*argv)[i],
								p->parameter_len);
					}
					else if ((*argv)[i][p->prefix_len] == '=')
					{
						strncpy((char*) p->parameter, (*argv)[i]
								+ p->prefix_len + 1, p->parameter_len);
					}
					(*argv)[i] = 0;
					break;
				case FUNCTION:
					((void(*)(struct parameter_tags[], const int)) ((void*) p->parameter))
					(p_, p->parameter_len);
				default:
					exit(0);
				}
				break;
			}
			p++;
		}
		if( p->parameter == NULL  )
		{
			static char __HELP__[] = "--help";
			if (strncmp((*argv)[i], __HELP__, sizeof(__HELP__))==0)
			{
				p = p_;
				printf("8888888888888888888888888888888888\n");
				while (p->parameter)
				{
					if (p->discribe)
					{
						printf( "%s\n",p->discribe );
					}
					p++;
				}
				printf("8888888888888888888888888888888888\n");
				exit(0);
				return;
			}
		}
		++i;
	}
	//删除已经分析的参数
	long a;
	a=i=0;
	while(i < *argc)
	{
		if(  (*argv)[i] )
			(*argv)[a++] =(*argv)[i];
		++i;
	}
	*argc = a;
}


