/*
 * ruijieAuthService.c
 *
 *  Created on: 2009-6-3
 *      Author: Alex Yang
 */

#include "ruijie_auth_service.h"
#include <unistd.h>

static void kill_all(char* process);
static void arg_parse(int argc, char *argv[]);
static void reg_signal();       //regist exit call bcak
static void check_for_root();   //check root right .

int main(int argc, char *argv[])
{
    //check_for_root();
    arg_parse(argc,argv);
    init_config();
    init_dbus();
    kill_all("ruijieAS");       //kill orher process
    kill_all("xgrsu");          //kill offical cilent


    reg_signal();

    //g_thread_create(run_1, arg, TRUE, NULL);
    //start g_loop.
    GMainLoop *mloop;
    mloop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(mloop);

}

/* kill other processes */
static void
kill_all(char* process){
    char cmd[256] = "";
    int cmd_return = 0 ;

    sprintf(cmd, "killall --signal 2 %s", process);
    cmd_return = system(cmd);
    if ( cmd_return < 0) {
        g_error("Killall Failure !") ;
    }
}

static void
reg_signal()
{
    signal(SIGHUP, logoff);
    signal(SIGINT, logoff);
    signal(SIGQUIT, logoff);
    signal(SIGABRT, logoff);
    signal(SIGKILL, logoff);
    signal(SIGTERM, logoff);
    signal(SIGSTOP, logoff);
    signal(SIGTSTP, logoff);
}

void logoff()
{
    disauth();
    exit(0);
}

static void check_for_root()
{
    if(geteuid()!=0)
        g_error("RuijieAS must be run as root.");
}
static void arg_parse(int argc, char *argv[])
{
    g_message("//TODO arg_parse");
}
