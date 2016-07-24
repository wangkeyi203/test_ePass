//
// Created by 王轲毅 on 16/7/24.
//

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>

#include "skf_test.h"
#define MODULE_NAME "my_pam"
#define PAM_DEBUG_ARG      1

#define DPRINT if ( PAM_DEBUG_ARG) my_syslog

#define PAM_RET_CHECK(ret) if(PAM_SUCCESS != ret)  {return ret; }

#ifdef _DEBUG
#define debug_printf(format, ...)	 printf(format, ##__VA_ARGS__)
#else
#define debug_printf(format, ...)
#endif

//if debug is setting this function can write log information /var/log/message
static void my_syslog (int err, const char *format, ...)
{
    va_list args;
    char buffer[1024];

    va_start (args, format);
    vsprintf (buffer, format, args);
    /* don't do openlog or closelog, but put our name in to be friendly */
    syslog (err, "%s: %s", MODULE_NAME, buffer);
    va_end (args);
}


void my_pam_free (pam_handle_t * pamh, void *pbuf, int error_status)
{
    free (pbuf);
}
int my_converse (pam_handle_t * pamh, int msg_style, char *message,
                 char **password)
{
    const struct pam_conv *conv;

    struct pam_message resp_message;
    const struct pam_message *msg[1];
    struct pam_response *resp = NULL;

    int retval;

    resp_message.msg_style = msg_style;
    resp_message.msg = message;
    msg[0] = &resp_message;
    //之前老提到对话函数,我们说过对话函数由应用程序提供,这里可以看到在模块中怎么获得对话函数
    //通过pam_get_item 可以获得pam_conv这个结构的一个指针(第二个参数是PAM_CONV表示类型)
    //然后就想下面的调用方式,你可以在你的模块中调用这个对话函数,和应用程序交互
    retval = pam_get_item (pamh, PAM_CONV, (const void **) &conv);
    PAM_RET_CHECK (retval)
    retval = conv->conv (1, msg, &resp, conv->appdata_ptr);
    PAM_RET_CHECK (retval) if (password)
    {
        *password = resp->resp;
        free (resp);
    }

    return PAM_SUCCESS;
}


#ifdef PAM_SM_AUTH
PAM_EXTERN int pam_sm_authenticate (pam_handle_t * pamh, int flags, int argc,
                                    const char **argv)
{
    const char *puser;
    char  *ppwd;
    int nret;
    int nloop;
    int nChallenge;
    int nValidrsp;
    char szbuf[256];
    char szconf[256];
    char *resp2challenge = NULL;

    int ctrl = 0;
    HANDLE g_hDev;
    HANDLE g_hApp;
    HANDLE m_hSessionKey;
    DEVINFO devInfo ;
    DEVINFO *DEVINFO = &devInfo;
    char * ret_fgets = NULL;


    FILE *fp;
    char line[100] = {'\0'};
    if((fp = fopen("/tmp/profile", "r"))== NULL)
    {
        perror("File open error\n");
        return PAM_SYSTEM_ERR;
    }

    memset (szconf, 0, 256);
    nret = pam_get_user (pamh, &puser, "UserName:");
    debug_printf("username=%s\n",puser);
    if (PAM_SUCCESS != nret)
    {
        printf("get user failed\n");
        int *pret = (int *) malloc (sizeof (int));
        //makelog("get username failed");
        DPRINT (LOG_DEBUG, "Get user name failed");
        *pret = nret;
        pam_set_data(pamh, "my_setcred_return", (void *)pret, my_pam_free);
        return PAM_SYSTEM_ERR;
    }
    debug_printf("get user success\n");

    while((ret_fgets = fgets(line, 100, fp)) != NULL)
    {
        int len = strlen(line);
        line[len-1] = '\0';
        char *token = strtok(line, ":");
        debug_printf("name = %s\n", token);
        if (!strcasecmp (token, puser))
        {
            token = strtok(NULL, ":");
            debug_printf("serialnu = %s\n", token);
            if(Test_ConnectDev(pamh,&g_hDev)!= 0)
            {
                debug_printf("test_devauth\n");
                int *pret = (int *) malloc (sizeof (int));
                //makelog("get username failed");
                DPRINT (LOG_DEBUG, "conncet dev  failed");
                *pret = 1;
                pam_set_data(pamh, "my_setcred_return", (void *)pret, my_pam_free);

                return PAM_SYSTEM_ERR;
            }

            if(Test_GetDevInfo_serialnu(g_hDev,&DEVINFO) ==0) {
                int *pret = (int *) malloc (sizeof (int));
                //makelog("get username failed");
                DPRINT (LOG_DEBUG, "Get devinfo  failed");
                *pret = 1;
                pam_set_data(pamh, "my_setcred_return", (void *)pret, my_pam_free);

                return PAM_SYSTEM_ERR;
            }
        }
        if(!strcasecmp(token, DEVINFO->SerialNumber))
            break;
    }
    if(ret_fgets == NULL)
    {
        int *pret = (int *) malloc (sizeof (int));
        //makelog("get username failed");
        DPRINT (LOG_DEBUG, "Get  file info failed");
        *pret = 1;
        pam_set_data(pamh, "my_setcred_return", (void *)pret, my_pam_free);
        return PAM_SYSTEM_ERR;
    }
/*
		if(Test_ConnectDev(pamh,&g_hDev)!= 0)
		{
			printf("test_devauth\n");
			return PAM_SYSTEM_ERR;
		}
*/
    if(Test_DevAuth(g_hDev, &m_hSessionKey) == 0)
    {
        int *pret = (int *) malloc (sizeof (int));
        //makelog("get username failed");
        DPRINT (LOG_DEBUG, "DevAuth  failed");
        *pret = 1;
        pam_set_data(pamh, "my_setcred_return", (void *)pret, my_pam_free);
        return PAM_SYSTEM_ERR;
    }
    debug_printf("test_devauth\n");
    if(Test_OpenApplication(g_hDev, &g_hApp) == 0)
    {
        int *pret = (int *) malloc (sizeof (int));
        //makelog("get username failed");
        DPRINT (LOG_DEBUG, "OpenApplication  failed");
        *pret = 1;
        pam_set_data(pamh, "my_setcred_return", (void *)pret, my_pam_free);
        return PAM_SYSTEM_ERR;
    }
    debug_printf("test_devauth\n");
    if(Test_VerifyPIN(pamh,g_hApp) == 0)
    {
        int *pret = (int *) malloc (sizeof (int));
        //makelog("get username failed");
        DPRINT (LOG_DEBUG, "VerifyPIN  failed");
        *pret = 1;
        pam_set_data(pamh, "my_setcred_return", (void *)pret, my_pam_free);
        return PAM_SYSTEM_ERR;
    }
    debug_printf("test_devauth\n");

    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
    int nret = PAM_SUCCESS, *pret;
    pret = &nret;
    pam_get_data (pamh, "my_setcred_return", (const void **) &pret);
    return *pret;
}
#endif //PAM_SM_AUTH
