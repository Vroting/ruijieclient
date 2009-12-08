//this is just a example case to show how to use the dbus.h

#include "dbus.h"
#include <stdio.h>

int print_state(){
	if (is_networ_ready()){
		printf("Now state is ready\n");
	}else{
		printf("Now state is NOT ready\n");
	}
	return 0;
}
int callback(){
	printf("I am Callllled~\n");
	print_state();
}

int main(int argc,char *argv[]){
	//初始化glib
	g_type_init();
	//准备好dbus的连接
	dbus_init();
	//把回调函数连接到信号上～
	connect_to_sig_StateChanged (&callback, NULL );
	print_state();
	//启动glib主循环，只有循环内才能收到信号。如果没有调用 g_loop_quit (void); 这个函数是不会返回的～
	g_loop_run();
	return 0;
}
