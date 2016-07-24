//
// Created by 王轲毅 on 16/7/24.
//

#include "SKFAPI.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include "pam_test.h"

#include "skf_test.h"
#define DEVNAME "ES3000GM VCR "
/*
HANDLE g_hDev;
HANDLE g_hApp;
HANDLE m_hSessionKey;
*/

#ifdef _DEBUG
#define debug_printf(format,...) printf(format, ##__VA_ARGS__)
#else
#define debug_printf(format,...)
#endif

void ShowErrInfo(DWORD dwErrInfo)
{
    printf("\n");
    switch(dwErrInfo)
    {
        case SAR_OK						    :  printf("succeed	\n");	break;
        case SAR_FAIL					    :  printf("failed               \n");	break;
        case SAR_UNKNOWNERR				    :  printf("unexpected error            \n");	break;
        case SAR_NOTSUPPORTYETERR		    :  printf("unsupport service        \n");	break;
        case SAR_FILEERR					:  printf("file error        \n");	break;
        case SAR_INVALIDHANDLEERR		    :  printf("invalid handle          \n");	break;
        case SAR_INVALIDPARAMERR			:  printf("invalid params          \n");	break;
        case SAR_READFILEERR				:  printf("read file error          \n");	break;
        case SAR_WRITEFILEERR			    :  printf("write file error          \n");	break;
        case SAR_NAMELENERR				    :  printf("invalid file name length        \n");	break;
        case SAR_KEYUSAGEERR				:  printf("key usage error        \n");	break;
        case SAR_MODULUSLENERR			    :  printf("modulus len error        \n");	break;
        case SAR_NOTINITIALIZEERR		    :  printf("not initialize            \n");	break;
        case SAR_OBJERR					    :  printf("object error            \n");	break;
        case SAR_MEMORYERR				    :  printf("memory error            \n");	break;
        case SAR_TIMEOUTERR				    :  printf("time out                \n");	break;
        case SAR_INDATALENERR			    :  printf("invalid inputdata len    \n");	break;
        case SAR_INDATAERR				    :  printf("invalid inputdata       \n");	break;
        case SAR_GENRANDERR				    :  printf("gen rand error      \n");	break;
        case SAR_HASHOBJERR				    :  printf("hash object error          \n");	break;
        case SAR_HASHERR					:  printf("hash failed        \n");	break;
        case SAR_GENRSAKEYERR			    :  printf("gen rsa key pair failed       \n");	break;
        case SAR_RSAMODULUSLENERR		    :  printf("invalid rsa modulus len     \n");	break;
        case SAR_CSPIMPRTPUBKEYERR		    :  printf("CSP service import key failed \n");	break;
        case SAR_RSAENCERR				    :  printf("RSA encrypt failed         \n");	break;
        case SAR_RSADECERR				    :  printf("RSA decrypt failed         \n");	break;
        case SAR_HASHNOTEQUALERR			:  printf("HASH value not equal        \n");	break;
        case SAR_KEYNOTFOUNTERR			    :  printf("not found key          \n");	break;
        case SAR_CERTNOTFOUNTERR			:  printf("not found cert          \n");	break;
        case SAR_NOTEXPORTERR			    :  printf("export object failed          \n");	break;
        case SAR_DECRYPTPADERR			    :  printf("padding of decrypt error    \n");	break;
        case SAR_MACLENERR				    :  printf("invalid MAC len         \n");	break;
        case SAR_BUFFER_TOO_SMALL		    :  printf("buffer too small          \n");	break;
        case SAR_KEYINFOTYPEERR			    :  printf("invalid key type        \n");	break;
        case SAR_NOT_EVENTERR			    :  printf("no event     \n");	break;
        case SAR_DEVICE_REMOVED			    :  printf("device removed          \n");	break;
        case SAR_PIN_INCORRECT			    :  printf("PIN incorrect           \n");	break;
        case SAR_PIN_LOCKED				    :  printf("PIN locked           \n");	break;
        case SAR_PIN_INVALID				:  printf("PIN invalid             \n");	break;
        case SAR_PIN_LEN_RANGE			    :  printf("PIN len range         \n");	break;
        case SAR_USER_ALREADY_LOGGED_IN	    :  printf("user already logged in        \n");	break;
        case SAR_USER_PIN_NOT_INITIALIZED   :  printf("pin not initialized  \n");	break;
        case SAR_USER_TYPE_INVALID		    :  printf("invalid PIN type         \n");	break;
        case SAR_APPLICATION_NAME_INVALID   :  printf("invalid application name        \n");	break;
        case SAR_APPLICATION_EXISTS		    :  printf("application exists        \n");	break;
        case SAR_USER_NOT_LOGGED_IN		    :  printf("user not logged in        \n");	break;
        case SAR_APPLICATION_NOT_EXISTS	    :  printf("application not exists          \n");	break;
        case SAR_FILE_ALREADY_EXIST		    :  printf("file already exist        \n");	break;
        case SAR_NO_ROOM					:  printf("no enough space            \n");	break;
        default								:  printf("unknown error        \n");  	break;
    }
}

#define SHOW_ERROR(x) \
        ShowErrInfo(x);

#define SHOW_ERROR_EX(x, y) \
        printf(x); \
        SHOW_ERROR(y);



BOOL Test_ConnectDev(pam_handle_t *pamh,HANDLE *g_hDev)
{
//	SHOW_PROCESS("ConnectDev");
    debug_printf("connectdev\n");

    ULONG ulBufSize = 0;
    ULONG ulReval = SKF_EnumDev(FALSE, NULL, &ulBufSize);
    debug_printf("Enum Devies...\n");
    if (ulBufSize != 0)
    {
        //vector<char> szNameList(ulBufSize, 0);
        char szNameList[20] = {'0'};
        if (SAR_OK != SKF_EnumDev(TRUE, (LPSTR)&szNameList[0], &ulBufSize))
        {
            printf("skf_enumdev faild\n");
            return FALSE;
        }

//		GetUtilities().ShowListInfo(&szNameList[0]);
        debug_printf("showlistinfo=%s\n",szNameList);


        int ulSelect = 0 ;
        char *ret;
/*
		printf("Input number to connect!(Example: 1 - "DEVNAME"1)");

		fflush(stdin);
		int ret = scanf("%d", &ulSelect);
		if(ret != 1)
		{
			printf("error input\n");
			return FALSE;
		}
*/


        int nret = my_converse (pamh, PAM_PROMPT_ECHO_ON, "Input number to connect!(Example: 1 - "DEVNAME"1)", &ret);

        if (PAM_SUCCESS != nret)
        {
            int *pret = (int *) malloc (sizeof (int));
            *pret = nret;
            printf ( "Get extra password failed");
            pam_set_data (pamh, "my_setcred_return", (void *) pret,my_pam_free);
            return 1 ;
        }
        ulSelect = atoi(ret);
        debug_printf("ulSelect = %d\n",ulSelect);
        char szTokenName[20] = {0};
        sprintf(szTokenName, DEVNAME"%d", ulSelect);
        debug_printf("szTokenNme = %s\n",szTokenName);
        ULONG ulReval = SKF_ConnectDev((LPSTR)szTokenName, g_hDev);
//		ULONG ulReval = SKF_ConnectDev((LPSTR)"ES3000GM ", g_hDev);

        if(SAR_OK != ulReval)
        {
            SHOW_ERROR(ulReval);
            printf("can not conncet usbkey\n");
            return 1;

        }
        printf("\nusbkey  have connect ...");
        return 0;
    }
    else{
        printf("no device\n");
        return 1;

    }

    // Check Arguments

}

BOOL Test_DevAuth(HANDLE g_hDev,HANDLE *m_hSessionKey)
{
    debug_printf("DevAuth\n");

    if (NULL == g_hDev)
    {
        printf("Please connect first!\n");
        return FALSE;
    }

    BYTE random[16] = {0};

    ULONG ulReval = SKF_GenRandom(g_hDev, random, 8);
    if (SAR_OK != ulReval)
    {
        SHOW_ERROR_EX("GenRandom", ulReval);
        return FALSE;
    }
    DEVINFO devInfo;
    ulReval = SKF_GetDevInfo(g_hDev, &devInfo);
    if (SAR_OK != ulReval)
    {
        SHOW_ERROR_EX("GetDevInfo", ulReval);
        return FALSE;
    }

    BYTE devKey[16] = {0};
    memcpy(devKey, (BYTE*)"1234567812345678", 16);
    ulReval = SKF_SetSymmKey(g_hDev, devKey, devInfo.DevAuthAlgId, m_hSessionKey);
    if (SAR_OK != ulReval)
    {
        SHOW_ERROR_EX("SetSymmKey", ulReval);
        return FALSE;
    }

    BLOCKCIPHERPARAM param = {0};
    ulReval = SKF_EncryptInit(*m_hSessionKey, param);
    if (SAR_OK != ulReval)
    {
        SHOW_ERROR_EX("EncryptInit", ulReval);
        return FALSE;
    }

    BYTE devkeyenc[16] = {0};
    DWORD dwResultLen = 16;
    ulReval = SKF_Encrypt(*m_hSessionKey, random, 16, devkeyenc, &dwResultLen);
    if (SAR_OK != ulReval)
    {
        SHOW_ERROR_EX("Encrypt", ulReval);
        return FALSE;
    }

    ulReval = SKF_DevAuth(g_hDev, devkeyenc, 16);
    debug_printf("dev ulreval=%d\n",ulReval);
    if(SAR_OK != ulReval)
    {
        SHOW_ERROR(ulReval);
    }

    return (SAR_OK == ulReval);
}


BOOL Test_OpenApplication(HANDLE g_hDev,HANDLE *g_hApp)
{
    debug_printf("OpenApplication\n");
    if (NULL == g_hDev)
    {
        printf("Please connect first!\n");
        return FALSE;
    }

    /* char szAppNames[256] = {0};
     printf("Input apps name to open!\n");

     fflush(stdin);
     gets(szAppNames);
 */

    ULONG ulReval = SKF_OpenApplication(g_hDev, (LPSTR)"usbkey", g_hApp);

    if(SAR_OK != ulReval)
    {
        SHOW_ERROR(ulReval);
    }

    return (SAR_OK == ulReval);
}


BOOL Test_GetDevInfo_serialnu(HANDLE g_hDev,DEVINFO **devInfo)
{
    debug_printf("GetDevInfo\n");

    if (NULL == g_hDev)
    {
        printf("Please connect first!\n");
        return FALSE;
    }

    ULONG ulReval = SKF_GetDevInfo(g_hDev, *devInfo);

    if(SAR_OK != ulReval)
    {
        SHOW_ERROR(ulReval);
    }

    if (SAR_OK == ulReval)
    {
        debug_printf("SerialNumber: %s\n", (*devInfo)->SerialNumber);
    }

    // Check Arguments

    return (SAR_OK == ulReval);
}

BOOL Test_VerifyPIN(pam_handle_t *pamh,HANDLE g_hApp)
{
    debug_printf("VerifyPIN\n");
    if (NULL == g_hApp)
    {
        printf("OPen application first!\n");
        return FALSE;
    }
/*
	int szBuf;
	ULONG nAccountType = 0;
	printf("Input 0: administrator, 1:User\n");

	fflush(stdin);
//	szBuf = getchar();
	szBuf = GetInputChar();

	if (szBuf == '0')
		nAccountType = 0;
	else if (szBuf == '1')
		nAccountType = 1;
	else
		return FALSE;
*/

//	printf("Input administrator  PIN:\n");
//	char szPIN[256] = {0};
    char *szPIN;
//	fflush(stdin);
    //fgets(szPIN, 255, stdin);
//	scanf("%s",szPIN);
    int nret = my_converse (pamh, PAM_PROMPT_ECHO_OFF, "Input usbkey administrator PIN:",&szPIN);

    if (PAM_SUCCESS != nret)
    {
        int *pret = (int *) malloc (sizeof (int));
        *pret = nret;
        printf ( "Get administrator PIN failed");
        pam_set_data (pamh, "my_setcred_return", (void *) pret,my_pam_free);
        return 1 ;
    }
    //int pin = atoi(szPIN);

    ULONG ulRetryCount = 0;
    ULONG ulReval = SKF_VerifyPIN(g_hApp, 0, (LPSTR)szPIN, &ulRetryCount);

    if(SAR_OK != ulReval)
    {
        SHOW_ERROR(ulReval);
    }

    return (SAR_OK == ulReval);
}
