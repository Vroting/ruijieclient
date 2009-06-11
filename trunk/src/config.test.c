/*******************************************************************************\
 * RuijieClient -- a CLI based Ruijie Client authentication modified from mystar *
 *                                                                               *
 * Copyright (C) Gong Han, Chen Tingjun  microcai                                        *
 \*******************************************************************************/

/*
 * This program is modified from MyStar, the original author is netxray@byhh.
 *
 * AUTHORS:
 *   Gong Han  <gong AT fedoraproject.org> from CSE@FJNU CN
 *   Chen Tingjun <chentingjun AT gmail.com> from POET@FJNU CN
 *   microcai <microcai AT sina DOT com > for ZSTU
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "sendpacket.h"
#include "ruijieclient.h"
#include <stdio.h>

static char fakeVersion[8];
//static char fakeMAC[32];
/*Check whether we have got enough configuration info*/
void
CheckConfig(ruijie_packet* l)
{
    if ((l->m_name == NULL) || (l->m_name[0] == 0))
    err_quit("invalid name found in ruijie.conf!\n");
    if ((l->m_password == NULL) || (l->m_password[0] == 0))
    err_quit("invalid password found in ruijie.conf!\n");
    if ((l->m_authenticationMode < 0) || (l->m_authenticationMode> 1))
    err_quit("invalid authenticationMode found in ruijie.conf!\n");
    if ((l->m_nic == NULL) || (strcmp(l->m_nic, "") == 0)
        || (strcmp(l->m_nic, "any") == 0))
    err_quit("invalid nic found in ruijie.conf!\n");
    if ((l->m_echoInterval < 0) || (l->m_echoInterval> 100))
    err_quit("invalid echo interval found in ruijie.conf!\n");
    //if ((m_intelligentReconnect < 0) || (m_intelligentReconnect> 1))
    if ((l->m_intelligentReconnect < 0))
    err_quit("invalid intelligentReconnect found in ruijie.conf!\n");

#ifdef DEBUG
    char buf[80];
    inet_ntop(AF_INET,&l->m_ip,buf,80);

	puts("-- CONF INFO");
    printf("## m_name=%s\n", l->m_name);
    printf("## m_password=%s\n", l->m_password);
    printf("## m_nic=%s\n", l->m_nic);
    printf("## m_authenticationMode=%d\n", l->m_authenticationMode);
    printf("## m_echoInterval=%d\n", l->m_echoInterval);
    printf("## m_intelligentReconnect=%d\n", l->m_intelligentReconnect);// NOT supported now!!
    printf("## m_fakeVersion=%s\n", l->m_fakeVersion);
    printf("## m_fakeAddress=%s\n",buf);
//    printf("## m_fakeMAC=%s\n",l->m_fakeMAC);
    puts("-- END");
#endif
}


int get_profile_string(FILE *fp,char *AppName,char *KeyName,char *KeyValue )
{
		int KEYVALLEN = 20 ;
        char appname[20],keyname[20];
        char buf[KEYVALLEN],*c;
        int found=0; /* 1 AppName 2 KeyName */


        fseek( fp, 0, SEEK_SET );

        sprintf( appname,"[%s]", AppName );
        memset( keyname, 0, sizeof(keyname) );
        while( !feof(fp) && fgets( buf, KEYVALLEN, fp )!=NULL ){
                //if( l_trim( buf )==0 )
                //        continue;

                if( found==0 ){
                        if( buf[0]!='[' ) {
                                continue;
                        } else if ( strncmp(buf,appname,strlen(appname))==0 ){
                                found=1;
                                continue;
                        }
                } else if( found==1 ){
                        if( buf[0]=='#' ){
                                continue;
                        } else if ( buf[0]=='[' ) {
                                break;
                        } else {
                                if( (c=(char*)strchr(buf,'='))==NULL )
                                        continue;
                                memset( keyname, 0, sizeof(keyname) );
                                sscanf( buf, "%[^=]", keyname );
                                if( strcmp(keyname, KeyName)==0 ){
                                        sscanf( ++c, "%[^\n]", KeyValue );
                                        found=2;
                                        break;
                                } else {
                                        continue;
                                }
                        }
                }
        }

        fclose( fp );

        if( found==2 )
                return(0);
        else
                return(-1);
}

void GetConfig(ruijie_packet * l)
{
	FILE *fp=fopen("./ruijie.ini","r" );
	get_profile_string(fp,"ruijieclient","m_name",l->m_name );
	//TODO 读取其他参数。。。。。。关闭文件
	//file_example:ruijie.ini
	//[ruijieclient]
	//m_name=aesfcfqfw
	//......

}

void GenSetting(){
//TODO
}
