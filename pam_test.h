//
// Created by 王轲毅 on 16/7/24.
//

#ifndef __PAM_TEST_H
#define __PAM_TEST_H
#define MODULE_NAME "pam_my"
#define SAMPLE_PROMPT "Extra Password for root:"
#define PAM_DEBUG_ARG      1

#define DPRINT if (ctrl & PAM_DEBUG_ARG) my_syslog

#define PAM_RET_CHECK(ret) if(PAM_SUCCESS != ret)  {return ret; }

int my_converse (pam_handle_t * pamh, int msg_style, char *message,char **password);
void my_pam_free (pam_handle_t * pamh, void *pbuf, int error_status);

#endif
