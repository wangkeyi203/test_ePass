//
// Created by 王轲毅 on 16/7/24.
//

#ifndef __SKF_TEST_H
#define __SKF_TEST_H
#include "SKFAPI.h"
#include <security/pam_modules.h>
#include <security/pam_appl.h>


BOOL Test_ConnectDev(pam_handle_t *pamh,HANDLE *g_hDev);
BOOL Test_GetDevInfo_serialnu(HANDLE g_hDev, DEVINFO **devinfo);
BOOL Test_DevAuth(HANDLE g_hDev, HANDLE *m_hSessionKey);
BOOL Test_OpenApplication(HANDLE g_hDev, HANDLE *g_hApp);
BOOL Test_VerifyPIN(pam_handle_t *pamh,HANDLE g_hApp);

#endif
