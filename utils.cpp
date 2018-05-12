//+-------------------------------------------------------------------------
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
//  File:       utils.cpp
//
//--------------------------------------------------------------------------

#include "setup.h"
#include "resource.h"
#include "common.h"

#include "msi.h"

#include <assert.h>
#include <tchar.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <strsafe.h>

#include <shlobj.h>
#include <Tlhelp32.h>
#include <shfolder.h>

// internet download
#include "wininet.h"  // DeleteUrlCacheEntry, InternetCanonicalizeUrl
#include "urlmon.h"   // URLDownloadToCacheFile

#define WIN // scope W32 API

/////////////////////////////////////////////////////////////////////////////
// VerifyFileSignature
//
DWORD VerifyFileSignature (LPCSTR lpszModule, __in_opt LPSTR lpszCmdLine)
{
    LPCSTR  pszFirstArgEnd;
    LPCSTR  pszFileName;
    LPCSTR  pszEnd;
    DWORD   Status;
    
    //
    // When this function is called, the first argument has already
    // been verified. So skip the first argument.
    //
    GetNextArgument (lpszCmdLine, NULL, &pszFirstArgEnd, NULL);
    
    // Now get the name of the file whose signature needs to be verified.
    Status = GetNextArgument (CharNextA(pszFirstArgEnd), &pszFileName, &pszEnd, NULL);
    
    // Must supply a filename
    if (ERROR_NO_MORE_ITEMS == Status)
        return ERROR_BAD_ARGUMENTS;
    
    // Should not have any more arguments
    if ('\0' != *(CharNextA(pszEnd)) &&
        ERROR_NO_MORE_ITEMS != GetNextArgument (CharNextA(CharNextA(pszEnd)), NULL, NULL, NULL))
    {
        return ERROR_BAD_ARGUMENTS;
    }
    
    // We have the right arguments. Null terminate the filename.
    *(CharNextA(pszEnd)) = '\0';
    
    switch (IsPackageTrusted(lpszModule, pszFileName, NULL))
    {
    case itvWintrustNotOnMachine:
        return TRUST_E_PROVIDER_UNKNOWN;
    case itvTrusted:
        return ERROR_SUCCESS;
    case itvUnTrusted:
    default:
        return TRUST_E_SUBJECT_NOT_TRUSTED;
    }
}

/////////////////////////////////////////////////////////////////////////////
// GetExecutionMode
//
emEnum GetExecutionMode (LPCSTR lpszCmdLine)
{
    LPCSTR  pszStart = NULL;
    LPCSTR  pszEnd = NULL;
    DWORD   dwStatus = ERROR_SUCCESS;
    bool    fQuoted = false;
    //
    // Check the first argument and set the execution mode accordingly.
    // When run without arguments, it is assumed that the default install
    // preset by the package publisher needs to be performed.
    //
    // In case an invalid option is provided, the help dialog describing the
    // usage must be displayed.
    //
    dwStatus = GetNextArgument (lpszCmdLine, &pszStart, &pszEnd, &fQuoted);
    
    if (ERROR_NO_MORE_ITEMS == dwStatus)
        return emPreset;
    
    // The only allowed values in the first argument are /a, /v and /?
    if (pszEnd != CharNextA(pszStart) || fQuoted)
        return emHelp;
    
    if ('/' != (*pszStart) && '-' != (*pszStart))
        return emHelp;
    
    switch (*pszEnd)
    {
    case 'a':
    case 'A':
        return emAdminInstall;
    case 'v':
    case 'V':
        return emVerify;
    default:
        return emHelp;
    }
}

/////////////////////////////////////////////////////////////////////////////
// GetNextArgument
//
DWORD GetNextArgument (LPCSTR pszCmdLine, LPCSTR *ppszArgStart, LPCSTR *ppszArgEnd, bool * pfQuoted)
{
    bool    fInQuotes = false;
    bool    fFoundArgEnd = false;
    LPCSTR  pszChar = pszCmdLine;
    LPCSTR  pszFirst = NULL;
    LPCSTR  pszLast = NULL;
    
    if (NULL == pszChar)
        return ERROR_NO_MORE_ITEMS;
    
    // Skip leading spaces.
    while (' ' == *pszChar || '\t' == *pszChar)
        pszChar = CharNextA(pszChar);
    
    // Check if we have run out of arguments.
    if ('\0' == (*pszChar))
        return ERROR_NO_MORE_ITEMS;
    
    // Check if we this argument has been enclosed in quotes
    if ('\"' == (*pszChar))
    {
        fInQuotes = true;
        pszChar = CharNextA (pszChar);
    }
        
    pszFirst = pszChar;
    
    // Now look for the end of the argument
    while (! fFoundArgEnd)
    {
        pszChar = CharNextA(pszChar);
        
        if ('\0' == (*pszChar))
            fFoundArgEnd = true;
        
        if (fInQuotes && '\"' == (*pszChar))
            fFoundArgEnd = true;
        
        if (!fInQuotes && ' ' == (*pszChar))
            fFoundArgEnd = true;
        
        if (!fInQuotes && '\t' == (*pszChar))
            fFoundArgEnd = true;
    }
    
    pszLast = CharPrevA (pszFirst, pszChar);
    
    if (ppszArgStart)
        *ppszArgStart = pszFirst;
    
    if (ppszArgEnd)
        *ppszArgEnd = pszLast;
    
    if (pfQuoted)
        *pfQuoted = fInQuotes;
    
    return ERROR_SUCCESS;
}

/////////////////////////////////////////////////////////////////////////////
//
//
DWORD GetAdminInstallInfo (bool fPatch, __in_opt LPSTR lpszCmdLine, LPCSTR * ppszAdminImagePath)
{
    LPCSTR  pszFirstArgEnd;
    LPCSTR  pszFileName;
    LPCSTR  pszEnd;
    DWORD   Status;
    
    //
    // When this function is called, the first argument has already been
    // verified. So skip the first argument.
    //
    GetNextArgument (lpszCmdLine, NULL, &pszFirstArgEnd, NULL);
    
    // See if there is another argument
    Status = GetNextArgument (CharNextA(pszFirstArgEnd), &pszFileName, &pszEnd, NULL);
    
    // If it is not a patch, there should not be any more arguments.
    if (!fPatch)
    {
        if (ERROR_NO_MORE_ITEMS != Status)
            return ERROR_BAD_ARGUMENTS;
        
        // If we are here, then we are done, because we have all the information we need.
        if (ppszAdminImagePath)
            *ppszAdminImagePath = NULL;
        return ERROR_SUCCESS;
    }
    
    // If we are here, this is a patch. Get the path to the admin. install.
    if (ERROR_NO_MORE_ITEMS == Status)
        return ERROR_BAD_ARGUMENTS;     // No path was supplied.
    
    // Should not have any more arguments.
    if ('\0' != *(CharNextA(pszEnd)) &&
        ERROR_NO_MORE_ITEMS != GetNextArgument (CharNextA(CharNextA(pszEnd)), NULL, NULL, NULL))
    {
        return ERROR_BAD_ARGUMENTS;
    }
    
    // We have the right arguments. Null terminate the pathname.
    *(CharNextA(pszEnd)) = '\0';
    
    if (ppszAdminImagePath)
        *ppszAdminImagePath = pszFileName;
    
    return ERROR_SUCCESS;
}

/////////////////////////////////////////////////////////////////////////////
// LoadResourceString
//
UINT LoadResourceString(HINSTANCE hInst, LPCSTR lpType, LPCSTR lpName, __out_ecount(*pdwBufSize) LPSTR lpBuf, DWORD *pdwBufSize)
{
    HRSRC   hRsrc   = 0;
    HGLOBAL hGlobal = 0;
    WCHAR   *pch    = 0;

    if ((hRsrc = WIN::FindResource(hInst, lpName, lpType)) != 0
        && (hGlobal = WIN::LoadResource(hInst, hRsrc)) != 0)
    {
        // resource exists
        if ((pch = (WCHAR*)LockResource(hGlobal)) != 0)
        {
            unsigned int cch = WideCharToMultiByte(CP_ACP, 0, pch, -1, NULL, 0, NULL, NULL);
            if (cch > *pdwBufSize)
            {
                *pdwBufSize = cch;
                return ERROR_MORE_DATA;
            }

            if (0 == WideCharToMultiByte(CP_ACP, 0, pch, -1, lpBuf, *pdwBufSize, NULL, NULL))
                return ERROR_FUNCTION_FAILED;
            *pdwBufSize = cch;

        }
        else
        {
            if (1 > *pdwBufSize)
            {
                *pdwBufSize = 1;
                return ERROR_MORE_DATA;
            }

            *pdwBufSize = 1;
            *lpBuf = 0;
        }
        
        DebugMsg("[Resource] lpName = %s, lpBuf = %s\n", lpName, lpBuf);

        return ERROR_SUCCESS;
    }

    // resource does not exist
    DebugMsg("[Resource] lpName = %s NOT FOUND\n", lpName);

    return ERROR_RESOURCE_NAME_NOT_FOUND;
}

/////////////////////////////////////////////////////////////////////////////
// SetupLoadResourceString
//

UINT SetupLoadResourceString(HINSTANCE hInst, LPCSTR lpName, __deref_out LPSTR *lppBuf, DWORD dwBufSize)
{
    UINT uiStat = 0;
    if (!*lppBuf)
    {
        dwBufSize = (dwBufSize > 0) ? dwBufSize : 256;
        *lppBuf = new char[dwBufSize];
        if (!*lppBuf)
            return ERROR_OUTOFMEMORY;
    }

    if (ERROR_SUCCESS != (uiStat = LoadResourceString(hInst, RT_INSTALL_PROPERTY, lpName, *lppBuf, &dwBufSize)))
    {
        if (uiStat != ERROR_MORE_DATA)
            return uiStat;

        // resize and try again
        delete [] *lppBuf;
        *lppBuf = new char[dwBufSize];
        if (!*lppBuf)
            return ERROR_OUTOFMEMORY;

        uiStat = LoadResourceString(hInst, RT_INSTALL_PROPERTY, lpName, *lppBuf, &dwBufSize);
    }

    return uiStat;
}

/////////////////////////////////////////////////////////////////////////////
// PostResourceNotFoundError
//

void PostResourceNotFoundError(HINSTANCE hInst, HWND hwndOwner, LPCSTR szTitle, LPCSTR szName)
{
    char szError[MAX_STR_LENGTH]  = {0};
    char szFormat[MAX_STR_LENGTH] = {0};

    WIN::LoadString(hInst, IDS_MISSING_RESOURCE, szFormat, sizeof(szFormat)/sizeof(char));
    StringCchPrintf(szError, sizeof(szError), szFormat, szName);
    MessageBox(hwndOwner, szError, szTitle, MB_OK | MB_ICONEXCLAMATION);
}

/////////////////////////////////////////////////////////////////////////////
// ReportUserCancelled
//

void ReportUserCancelled(HINSTANCE hInst, HWND hwndOwner, LPCSTR szTitle)
{
    char szError[MAX_STR_LENGTH] = {0};

    WIN::LoadString(hInst, IDS_USER_CANCELLED, szError, sizeof(szError)/sizeof(char));
    MessageBox(hwndOwner, szError, szTitle, MB_OK | MB_ICONEXCLAMATION);
}

/////////////////////////////////////////////////////////////////////////////
// PostError
//

void PostError(HINSTANCE hInst, HWND hwndOwner, LPCSTR szTitle, UINT uiErrorId)
{
    char szError[MAX_STR_LENGTH]  = {0};

    WIN::LoadString(hInst, uiErrorId, szError, sizeof(szError)/sizeof(char));
    MessageBox(hwndOwner, szError, szTitle, MB_OK | MB_ICONERROR);
}

/////////////////////////////////////////////////////////////////////////////
// PostError
//

void PostError(HINSTANCE hInst, HWND hwndOwner, LPCSTR szTitle, UINT uiErrorId, LPCSTR szValue)
{
    char szError[MAX_STR_LENGTH]  = {0};
    char szFormat[MAX_STR_LENGTH] = {0};

    WIN::LoadString(hInst, uiErrorId, szFormat, sizeof(szFormat)/sizeof(char));
    StringCchPrintf(szError, sizeof(szError), szFormat, szValue);
    MessageBox(hwndOwner, szError, szTitle, MB_OK | MB_ICONERROR);
}

/////////////////////////////////////////////////////////////////////////////
// PostError
//

void PostError(HINSTANCE hInst, HWND hwndOwner, LPCSTR szTitle, UINT uiErrorId, LPCSTR szValue, int iValue)
{
    char szError[MAX_STR_LENGTH]  = {0};
    char szFormat[MAX_STR_LENGTH] = {0};

    WIN::LoadString(hInst, uiErrorId, szFormat, sizeof(szFormat)/sizeof(char));
    StringCchPrintf(szError, sizeof(szError), szFormat, szValue, iValue);
    MessageBox(hwndOwner, szError, szTitle, MB_OK | MB_ICONERROR);
}

/////////////////////////////////////////////////////////////////////////////
// PostError
//

void PostError(HINSTANCE hInst, HWND hwndOwner, LPCSTR szTitle, UINT uiErrorId, int iValue)
{
    char szError[MAX_STR_LENGTH]  = {0};
    char szFormat[MAX_STR_LENGTH] = {0};

    WIN::LoadString(hInst, uiErrorId, szFormat, sizeof(szFormat)/sizeof(char));
    StringCchPrintf(szError, sizeof(szError), szFormat, iValue);
    MessageBox(hwndOwner, szError, szTitle, MB_OK | MB_ICONERROR);
}

/////////////////////////////////////////////////////////////////////////////
// PostFormattedError
//

void PostFormattedError(HINSTANCE hInst, HWND hwndOwner, LPCSTR szTitle, UINT uiErrorId, LPCSTR szValue)
{
    char szFormat[MAX_STR_LENGTH] = {0};
    const char* szArgs[1] = {szValue};
    LPVOID lpMessage = 0;;

    WIN::LoadString(hInst, uiErrorId, szFormat, sizeof(szFormat)/sizeof(char));
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY, (LPVOID)szFormat, 0, 0, (LPSTR)&lpMessage, 0, (va_list*)szArgs);
    if (!lpMessage)
    {
        ReportErrorOutOfMemory(hInst, hwndOwner, szTitle);
        return;
    }
    MessageBox(hwndOwner, (LPCSTR)lpMessage, szTitle, MB_OK | MB_ICONERROR);
    LocalFree(lpMessage);
}

/////////////////////////////////////////////////////////////////////////////
// PostMsiError
//

void PostMsiError(HINSTANCE hInst, HINSTANCE hMsi, HWND hwndOwner, LPCSTR szTitle, UINT uiErrorId)
{
    switch (uiErrorId)
    {
    case ERROR_INSTALL_SUSPEND:
    case ERROR_INSTALL_USEREXIT:
    case ERROR_INSTALL_FAILURE:
    case ERROR_SUCCESS_REBOOT_REQUIRED:
    case ERROR_SUCCESS_REBOOT_INITIATED:
    case ERROR_APPHELP_BLOCK:
        break;
    case ERROR_FILE_NOT_FOUND:
    case ERROR_INVALID_NAME:
    case ERROR_PATH_NOT_FOUND:
        uiErrorId = ERROR_INSTALL_PACKAGE_OPEN_FAILED;
    default:
        {
            char szError[MAX_STR_LENGTH] = {0};
            if (0 == WIN::LoadString(hMsi, uiErrorId, szError, sizeof(szError)/sizeof(char)))
            {
                // error string does not exist, use default
                PostError(hInst, hwndOwner, szTitle, IDS_INSTALL_ERROR, uiErrorId);
            }
            else
            {
                MessageBox(hwndOwner, szError, szTitle, MB_OK | MB_ICONERROR);
            }
            return;
        }
    }
}

/////////////////////////////////////////////////////////////////////////////
// IsTerminalServerInstalled
//
//  Determines whether terminal services are installed
//
bool IsTerminalServerInstalled(bool fWin9X, int iMajorVersion)
{
    const char szTSSearchStr[]   = TEXT("Terminal Server"); // Not localized
    const char szKey[]         = TEXT("System\\CurrentControlSet\\Control\\ProductOptions");
    const char szValue[]       = TEXT("ProductSuite");

    DWORD dwSize = 0;
    HKEY  hKey = 0;
    DWORD dwType = 0;

    // Win9X is not terminal server
    if (fWin9X)
        return false;

    bool fIsTerminalServer = false;

    // On Windows 2000 and greater, the ProductSuite "Terminal Server"
    // value will always be present. Use GetVersionEx to get the right
    // answer.
    if (iMajorVersion > 4)
    {
        OSVERSIONINFOEX osVersionInfo;
        DWORDLONG dwlConditionMask = 0;

        ZeroMemory(&osVersionInfo, sizeof(OSVERSIONINFOEX));
        osVersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

        if (GetVersionEx((OSVERSIONINFO*)&osVersionInfo)
            && (osVersionInfo.wSuiteMask & VER_SUITE_TERMINAL)
            && !(osVersionInfo.wSuiteMask & VER_SUITE_SINGLEUSERTS))
            fIsTerminalServer = true;
    }
    else
    {
        // Other NT versions, check the registry key
        // If the value we want exists and has a non-zero size...

        if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKey, 0, KEY_READ, &hKey)
            && ERROR_SUCCESS == RegQueryValueEx(hKey, szValue, NULL, &dwType, NULL, &dwSize)
            && dwSize > 0
            && REG_MULTI_SZ == dwType)
        {
            char* szSuiteList = new char[dwSize];
            if (szSuiteList)
            {
                ZeroMemory(szSuiteList, dwSize);
                if (ERROR_SUCCESS == RegQueryValueEx(hKey, szValue, NULL, &dwType, (LPBYTE)szSuiteList, &dwSize))
                {
                    DWORD cchMulti = 0;                    // Length of current member
                    DWORD cchSrch  = lstrlen(szTSSearchStr);    // Constant during search
                    const char *szSubString = szSuiteList; // pointer to current substring

                    while (*szSubString) // Break on consecutive zero bytes
                    {
                        cchMulti = lstrlen(szSubString);
                        if (cchMulti == cchSrch && 0 == lstrcmp(szTSSearchStr, szSubString))
                        {
                            fIsTerminalServer = true;
                            break;
                        }

                        // substring does not match, skip forward the length of the substring
                        // plus 1 for the terminating null.
                        szSubString += (cchMulti + 1);
                    }
                }
                delete [] szSuiteList;
            }
        }

        if (hKey)
            RegCloseKey(hKey);
    }

    return fIsTerminalServer;
}

/////////////////////////////////////////////////////////////////////////////
// AlreadyInProgress
//
//  Attempts to create the MSISETUP mutex. Returns TRUE
//  if mutex already exists or failed to create mutex
//

/*
bool AlreadyInProgress(HANDLE& hMutex)
{
    const char *szMutexName = "Global\\_MSISETUP_{2956EBA1-9B5A-4679-8618-357136DA66CA}";
*/
//    hMutex = WIN::CreateMutex(NULL /*default security descriptor*/, FALSE, szMutexName);
/*
    if (!hMutex || ERROR_ALREADY_EXISTS == GetLastError())
        return true;

    return false;
}
*/
bool AlreadyInProgress(bool fWin9X, int iMajorVersion, HANDLE& hMutex)
{
    const char szTSUniqueName[] = "Global\\_MSISETUP_{2956EBA1-9B5A-4679-8618-357136DA66CA}";
    const char szUniqueName[] = "_MSISETUP_{2956EBA1-9B5A-4679-8618-357136DA66CA}";

    // if Windows 2000 or greater or Terminal Server installed, must use Global prefix
    const char *szMutexName = NULL;
    if ((!fWin9X && iMajorVersion >= 5) || IsTerminalServerInstalled(fWin9X, iMajorVersion))
        szMutexName = szTSUniqueName;
    else
        szMutexName = szUniqueName;


    hMutex = WIN::CreateMutex(NULL /*default security descriptor*/, FALSE, szMutexName);
    if (!hMutex || ERROR_ALREADY_EXISTS == GetLastError())
        return true;


    return false;
}

/////////////////////////////////////////////////////////////////////////////
// DisplayUsage
//
void DisplayUsage (HINSTANCE hInst, HWND hwndOwner, LPCSTR szCaption)
{
    char szMessage[MAX_STR_LENGTH];

    WIN::LoadString(hInst, IDS_USAGE, szMessage, sizeof(szMessage)/sizeof(char));
    WIN::MessageBox(hwndOwner, szMessage, szCaption, MB_OK | MB_ICONINFORMATION);
}

/////////////////////////////////////////////////////////////////////////////
// ReportErrorOutOfMemory
//

void ReportErrorOutOfMemory(HINSTANCE hInst, HWND hwndOwner, LPCSTR szCaption)
{
    char szError[MAX_STR_LENGTH];

    WIN::LoadString(hInst, IDS_OUTOFMEM, szError, sizeof(szError)/sizeof(char));
    WIN::MessageBox(hwndOwner, szError, szCaption, MB_OK | MB_ICONERROR);
}


/////////////////////////////////////////////////////////////////////////////
// GetFileVersionNumber
//

DWORD GetFileVersionNumber(__in LPSTR szFilename, DWORD * pdwMSVer, DWORD * pdwLSVer)
{
    DWORD             dwResult = NOERROR;
    unsigned          uiSize;
    DWORD             dwVerInfoSize;
    DWORD             dwHandle;
    BYTE              *prgbVersionInfo = NULL;
    VS_FIXEDFILEINFO  *lpVSFixedFileInfo = NULL;

    DWORD dwMSVer = 0xffffffff;
    DWORD dwLSVer = 0xffffffff;

    dwVerInfoSize = GetFileVersionInfoSize(szFilename, &dwHandle);
    if (0 != dwVerInfoSize)
    {
        prgbVersionInfo = (LPBYTE) WIN::GlobalAlloc(GPTR, dwVerInfoSize);
        if (NULL == prgbVersionInfo)
        {
            dwResult = ERROR_NOT_ENOUGH_MEMORY;
            goto Finish;
        }

        // Read version stamping info
        if (GetFileVersionInfo(szFilename, dwHandle, dwVerInfoSize, prgbVersionInfo))
        {
            // get the value for Translation
            if (VerQueryValue(prgbVersionInfo, "\\", (LPVOID*)&lpVSFixedFileInfo, &uiSize) && (uiSize != 0))
            {
                dwMSVer = lpVSFixedFileInfo->dwFileVersionMS;
                dwLSVer = lpVSFixedFileInfo->dwFileVersionLS;
            }
        }
        else
        {
            dwResult = GetLastError();
            goto Finish;
        }
    }
    else
    {
        dwResult = GetLastError();
    }

#ifdef DEBUG
    char szVersion[255];
    StringCchPrintf(szVersion, sizeof(szVersion), "%s is version %d.%d.%d.%d\n", szFilename, HIWORD(dwMSVer), LOWORD(dwMSVer), HIWORD(dwLSVer), LOWORD(dwLSVer));
    DebugMsg("[INFO] %s", szVersion);
#endif // DEBUG

Finish:
    if (NULL != prgbVersionInfo)
        WIN::GlobalFree(prgbVersionInfo);
    if (pdwMSVer)
        *pdwMSVer = dwMSVer;
    if (pdwLSVer)
        *pdwLSVer = dwLSVer;

    return dwResult;
}

/*
/////////////////////////////////////////////////////////////////////////////
// MimimumWindowsPlatform
//
//  Returns true if running on a platform whose major version, minor version
//  and service pack major are greater than or equal to the ones specifed
//  while making this function call
//
bool MimimumWindowsPlatform(DWORD dwMajorVersion, DWORD dwMinorVersion, WORD wServicePackMajor)
{
   OSVERSIONINFOEX osvi;
   DWORDLONG dwlConditionMask = 0;

   // Initialize the OSVERSIONINFOEX structure.
   ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
   osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
   osvi.dwMajorVersion = dwMajorVersion;
   osvi.dwMinorVersion = dwMinorVersion;
   osvi.wServicePackMajor = wServicePackMajor;
   
   // Initialize the condition mask.
   VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, VER_GREATER_EQUAL);
   VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, VER_GREATER_EQUAL);
   VER_SET_CONDITION(dwlConditionMask, VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);
 
   // Perform the test.
   return VerifyVersionInfo(&osvi, 
                            VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR,
                            dwlConditionMask) ? true : false;
}

/////////////////////////////////////////////////////////////////////////////
// IsOSSupported
//
//  Returns true if running on Windows 2003, Windows XP or 
//  Windows 2000 SP3 and above. Else returns false
//
bool IsOSSupported()
{
    OSVERSIONINFO sInfoOS;
    memset((void*)&sInfoOS, 0x00, sizeof(OSVERSIONINFO));

    sInfoOS.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    WIN::GetVersionEx(&sInfoOS);

    // We do no support any platform prior to Windows 2000
    if (5 > sInfoOS.dwMajorVersion)
        return false;

    // We support:
    if(MimimumWindowsPlatform(5, 2, 0) ||   // Windows 2003 and above
       MimimumWindowsPlatform(5, 1, 0) ||   // Windows XP and above
       MimimumWindowsPlatform(5, 0, 3))     // Windows 2000 SP3 and above
        return true;
    else
        return false;
}
*/

/////////////////////////////////////////////////////////////////////////////
// IsOSWin9X
//
//  Returns true if running on a Win9X platform
//  Returns false if running on a WinNT platform
//

bool IsOSWin9X(int *piMajVer, int *piMinVer)
{
    OSVERSIONINFO sInfoOS;
    memset((void*)&sInfoOS, 0x00, sizeof(OSVERSIONINFO));

    sInfoOS.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    WIN::GetVersionEx(&sInfoOS);

    if (piMajVer)
        *piMajVer = sInfoOS.dwMajorVersion;
    if (piMinVer)
	    if (VER_PLATFORM_WIN32_NT == sInfoOS.dwPlatformId)
		    *piMinVer = sInfoOS.dwMinorVersion;
		else
		    *piMinVer = LOBYTE(HIWORD(sInfoOS.dwBuildNumber));

    if (VER_PLATFORM_WIN32_NT == sInfoOS.dwPlatformId)
        return false;
    else
        return true;
}

//--------------------------------------------------------------------------------------
// ADVAPI32 API -- delay load
//--------------------------------------------------------------------------------------

#define ADVAPI32_DLL "advapi32.dll"

#define ADVAPI32API_CheckTokenMembership "CheckTokenMembership"
typedef BOOL (WINAPI* PFnCheckTokenMembership)(HANDLE TokenHandle, PSID SidToCheck, PBOOL IsMember);

#define ADVAPI32API_AdjustTokenPrivileges "AdjustTokenPrivileges"
typedef BOOL (WINAPI* PFnAdjustTokenPrivileges)(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);

#define ADVAPI32API_OpenProcessToken "OpenProcessToken"
typedef BOOL (WINAPI* PFnOpenProcessToken)(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);

#define ADVAPI32API_LookupPrivilegeValue "LookupPrivilegeValueA"
typedef BOOL (WINAPI* PFnLookupPrivilegeValue)(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);

/////////////////////////////////////////////////////////////////////////////
// IsAdmin
//
//  Returns true if current user is an administrator (or if on Win9X)
//  Returns false if current user is not an adminstrator
//
//  implemented as per KB Q118626
//

/*
bool IsAdmin()
{
    // get the administrator sid
    PSID psidAdministrators;
    SID_IDENTIFIER_AUTHORITY siaNtAuthority = SECURITY_NT_AUTHORITY;
    if(!AllocateAndInitializeSid(&siaNtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &psidAdministrators))
        return false;

    // on NT5, use the CheckTokenMembershipAPI to correctly handle cases where
    // the Adiminstrators group might be disabled. bIsAdmin is BOOL for 
    BOOL bIsAdmin = FALSE;
    // CheckTokenMembership checks if the SID is enabled in the token. NULL for
    // the token means the token of the current thread. Disabled groups, restricted
    // SIDS, and SE_GROUP_USE_FOR_DENY_ONLY are all considered. If the function
    // returns false, ignore the result.

    HMODULE hAdvapi32 = LoadLibrary(ADVAPI32_DLL);
    if (!hAdvapi32)
        bIsAdmin = FALSE;
    else
    {
        PFnCheckTokenMembership pfnCheckTokenMembership = (PFnCheckTokenMembership)GetProcAddress(hAdvapi32, ADVAPI32API_CheckTokenMembership);
        if (!pfnCheckTokenMembership || !pfnCheckTokenMembership(NULL, psidAdministrators, &bIsAdmin))
            bIsAdmin = FALSE;
    }
    FreeLibrary(hAdvapi32);
    hAdvapi32 = 0;
    
    WIN::FreeSid(psidAdministrators);
    return bIsAdmin ? true : false;

}
*/
bool IsAdmin(bool fWin9X, int iMajorVersion)
{
    if (fWin9X)
    {
        // convention: always admin on Win9X
        return true;
    }

    // get the administrator sid
    PSID psidAdministrators;
    SID_IDENTIFIER_AUTHORITY siaNtAuthority = SECURITY_NT_AUTHORITY;
    if(!AllocateAndInitializeSid(&siaNtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &psidAdministrators))
        return false;

    // on NT5, use the CheckTokenMembershipAPI to correctly handle cases where
    // the Adiminstrators group might be disabled. bIsAdmin is BOOL for 
    BOOL bIsAdmin = FALSE;
    if (iMajorVersion >= 5) 
    {
        // CheckTokenMembership checks if the SID is enabled in the token. NULL for
        // the token means the token of the current thread. Disabled groups, restricted
        // SIDS, and SE_GROUP_USE_FOR_DENY_ONLY are all considered. If the function
        // returns false, ignore the result.

        HMODULE hAdvapi32 = LoadLibrary(ADVAPI32_DLL);
        if (!hAdvapi32)
            bIsAdmin = FALSE;
        else
        {
            PFnCheckTokenMembership pfnCheckTokenMembership = (PFnCheckTokenMembership)GetProcAddress(hAdvapi32, ADVAPI32API_CheckTokenMembership);
            if (!pfnCheckTokenMembership || !pfnCheckTokenMembership(NULL, psidAdministrators, &bIsAdmin))
                bIsAdmin = FALSE;
        }
        FreeLibrary(hAdvapi32);
        hAdvapi32 = 0;
    }
    else
    {
        // NT4, check groups of user
        HANDLE hAccessToken = 0;
        UCHAR *szInfoBuffer = new UCHAR[1024]; // may need to resize if TokenInfo too big
        DWORD dwInfoBufferSize = 1024;
        DWORD dwRetInfoBufferSize = 0;
        UINT x=0;

        if (szInfoBuffer && WIN::OpenProcessToken(WIN::GetCurrentProcess(), TOKEN_READ, &hAccessToken))
        {
            bool bSuccess = false;
            bSuccess = WIN::GetTokenInformation(hAccessToken, TokenGroups, szInfoBuffer, dwInfoBufferSize, &dwRetInfoBufferSize) == TRUE;

            if(dwRetInfoBufferSize > dwInfoBufferSize)
            {
                delete [] szInfoBuffer;
                szInfoBuffer = new UCHAR[dwRetInfoBufferSize];
                if (szInfoBuffer)
                {
                    dwInfoBufferSize = dwRetInfoBufferSize;
                    bSuccess = WIN::GetTokenInformation(hAccessToken, TokenGroups, szInfoBuffer, dwInfoBufferSize, &dwRetInfoBufferSize) == TRUE;
                }
            }

            WIN::CloseHandle(hAccessToken);
            
            if (bSuccess)
            {
                PTOKEN_GROUPS ptgGroups = (PTOKEN_GROUPS)(UCHAR*)szInfoBuffer;
                for(x=0;x<ptgGroups->GroupCount;x++)
                {
                    if( WIN::EqualSid(psidAdministrators, ptgGroups->Groups[x].Sid) )
                    {
                        bIsAdmin = TRUE;
                        break;
                    }

                }
            }
        }
    }
    
    WIN::FreeSid(psidAdministrators);
    return bIsAdmin ? true : false;

}

/////////////////////////////////////////////////////////////////////////////
// AcquireShutdownPrivilege
//
//  Attempts to enable the SE_SHUTDOWN_NAME privilege in the process token
//
bool AcquireShutdownPrivilege()
{
    HANDLE hToken = 0;
    TOKEN_PRIVILEGES tkp;

    HMODULE hAdvapi32 = LoadLibrary(ADVAPI32_DLL);
    if (!hAdvapi32)
        return false;

    PFnOpenProcessToken pfnOpenProcessToken = (PFnOpenProcessToken)GetProcAddress(hAdvapi32, ADVAPI32API_OpenProcessToken);
    PFnLookupPrivilegeValue pfnLookupPrivilegeValue = (PFnLookupPrivilegeValue)GetProcAddress(hAdvapi32, ADVAPI32API_LookupPrivilegeValue);
    PFnAdjustTokenPrivileges pfnAdjustTokenPrivileges = (PFnAdjustTokenPrivileges)GetProcAddress(hAdvapi32, ADVAPI32API_AdjustTokenPrivileges);
    if (!pfnOpenProcessToken || !pfnLookupPrivilegeValue || !pfnAdjustTokenPrivileges)
    {
        FreeLibrary(hAdvapi32);
        return false;
    }

    // grab this process's token
    if (!pfnOpenProcessToken(WIN::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        FreeLibrary(hAdvapi32);
        return false;
    }

    // get the LUID for the shutdown privilege
    pfnLookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);

    tkp.PrivilegeCount = 1; // one privilege to set
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // get the shutdown privilege for this process
    pfnAdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);

    // cannot test return value of AdjustTokenPrivileges
    if (ERROR_SUCCESS != WIN::GetLastError())
    {
        FreeLibrary(hAdvapi32);
        return false;
    }

    FreeLibrary(hAdvapi32);

    return true;
}

/////////////////////////////////////////////////////////////////////////////
// SetDiagnosticMode
//
//  Turns on debug output if first char of szDebugEnvVar is set to 1
//

int g_dmDiagnosticMode = -1; // -1 until set, then DebugMsg skips fn call if 0

void SetDiagnosticMode()
{
    g_dmDiagnosticMode = 0; // disable DebugMsg to start

    char rgchBuf[64] = {0};
    if (0 != WIN::GetEnvironmentVariable(szDebugEnvVar, rgchBuf, sizeof(rgchBuf)/sizeof(char))
        && rgchBuf[0] == '1')
    {
        g_dmDiagnosticMode = 1; // enable DebugMsg output
    }
}

/////////////////////////////////////////////////////////////////////////////
// DebugMsg
//
//  Outputs debugging string to debugger if debug output is enabled
//

void DebugMsg(LPCSTR szFormat, int iArg1)
{
    if (-1 == g_dmDiagnosticMode)
    {
        SetDiagnosticMode();
    }

    if (0 == g_dmDiagnosticMode || !szFormat)
        return; // debug output is not enabled or nothing to output

    const int INT_AS_STRING_SIZE = 12;
    size_t cchFormat = lstrlen(szFormat);
    size_t cchDebug = cchFormat + INT_AS_STRING_SIZE + 1;
    char *szDebug = new char[cchDebug];
    if (!szDebug)
        return ; // out of memory

    if (FAILED(StringCchPrintf(szDebug, cchDebug, szFormat, iArg1)))
    {
        delete[] szDebug;
        return;
    }
    OutputDebugString(szDebug);
    return;
}

void DebugMsg(LPCSTR szFormat, int iArg1, int iArg2)
{
    if (-1 == g_dmDiagnosticMode)
    {
        SetDiagnosticMode();
    }

    if (0 == g_dmDiagnosticMode || !szFormat)
        return; // debug output is not enabled or nothing to output

    const int INT_AS_STRING_SIZE = 12;
    size_t cchFormat = lstrlen(szFormat);
    size_t cchDebug = cchFormat + 2 * INT_AS_STRING_SIZE + 1;
    char *szDebug = new char[cchDebug];
    if (!szDebug)
        return ; // out of memory

    if (FAILED(StringCchPrintf(szDebug, cchDebug, szFormat, iArg1, iArg2)))
    {
        delete[] szDebug;
        return;
    }
    OutputDebugString(szDebug);
    return;
}

void DebugMsg(LPCSTR szFormat, LPCSTR szArg1, LPCSTR szArg2)
{
    if (-1 == g_dmDiagnosticMode)
    {
        SetDiagnosticMode();
    }

    if (0 == g_dmDiagnosticMode || !szFormat)
        return; // debug output is not enabled or nothing to output

    size_t cchFormat = lstrlen(szFormat);
    size_t cchArg1 = (szArg1 != 0) ? lstrlen(szArg1) : 0;
    size_t cchArg2 = (szArg2 != 0) ? lstrlen(szArg2) : 0;

    if (0 == cchArg1)
    {
        OutputDebugString(szFormat);
    }
    else
    {
        size_t cchDebug = cchFormat + cchArg1 + cchArg2 + 1;
        char *szDebug = new char[cchDebug];
        if (!szDebug)
            return ; // out of memory
        if (0 == cchArg2)
        {            
            if (FAILED(StringCchPrintf(szDebug, cchDebug, szFormat, szArg1)))
            {
                delete[] szDebug;
                return;
            }
            OutputDebugString(szDebug);
        }
        else
        {
            if (FAILED(StringCchPrintf(szDebug, cchDebug, szFormat, szArg1, szArg2)))
            {
                delete[] szDebug;
                return;
            }
            OutputDebugString(szDebug);
        }
    }

    return;
}

/////////////////////////////////////////////////////////////////////////////
// GetFNameFromFPath
//
LPCSTR GetFNameFromFPath(LPCSTR szFPath, size_t cchMax)
{
	int i;
	size_t cch;

	if (SUCCEEDED(StringCchLength(szFPath, cchMax, &cch)))
		for (i = cch - 1; i >= 0; i --)
			if (szFPath[i] == '\\')
				break;

	return (LPSTR)szFPath + i + 1;
}

/////////////////////////////////////////////////////////////////////////////
// GetDPathFromFPath
//
void GetDPathFromFPath(LPCSTR szFPath, size_t cchMaxFPath, LPSTR szDPath, size_t cchMaxDPath)
{
	size_t cchFPath;

	*szDPath = '\0';
	if (SUCCEEDED(StringCchLength(szFPath, cchMaxFPath, &cchFPath))) {
		int nPathSepIndex = 0;
		for (int i = 0, imax = cchFPath; i < imax; i ++)
			if (szFPath[i] == '\\')
				nPathSepIndex = i;
		StringCchCopyN(szDPath, cchMaxDPath, szFPath, nPathSepIndex);
	}
}

/////////////////////////////////////////////////////////////////////////////
// GetCommandDPathFromCommandLine
//
void GetCommandDPathFromCommandLine(LPCSTR szCommandLine, size_t cchMaxCommandLine, LPSTR szCommandDPath, size_t cchMaxCommandDPath)
{
	size_t cchCommandLine;

	*szCommandDPath = '\0';
	if (SUCCEEDED(StringCchLength(szCommandLine, cchMaxCommandLine, &cchCommandLine))) {
		int i;
		int imax;
		BOOL bQuote = FALSE;
		BOOL bBreak = FALSE;
		for (i = 0, imax = cchCommandLine; i < imax; i ++) {
			switch (szCommandLine[i]) {
			case '\"':
				bQuote = ! bQuote;
				break;
			case ' ':
				if (! bQuote)
					bBreak = TRUE;
			}
			if (bBreak)
				break;
		}
		char *szCommandFPath = new char[i + 1];
		if (szCommandFPath) {
			int nQuote = *szCommandLine == '\"' ? 1 : 0;
			StringCchCopyN(szCommandFPath, i + 1, szCommandLine + nQuote, i - nQuote * 2);
			GetDPathFromFPath(szCommandFPath, i + 1, szCommandDPath, cchMaxCommandDPath);
			delete [] szCommandFPath;
		}
	}
}

/////////////////////////////////////////////////////////////////////////////
// ExecuteCommandLine
//
DWORD ExecuteCommandLine(LPSTR szCommandLine, bool fWaitForProcess)
{
    DWORD dwResult = 0;

    // build up CreateProcess structures
    STARTUPINFO          sui;
    PROCESS_INFORMATION  pi;

    memset((void*)&pi, 0x00, sizeof(PROCESS_INFORMATION));
    memset((void*)&sui, 0x00, sizeof(STARTUPINFO));
    sui.cb          = sizeof(STARTUPINFO);
    sui.dwFlags     = STARTF_USESHOWWINDOW;
    sui.wShowWindow = SW_SHOW;

    DWORD cchWorkingDir = lstrlen(szCommandLine) + 1;
    char *szWorkingDir = 0;
    
    szWorkingDir = new char[cchWorkingDir];

    if (!szWorkingDir)
    {
        dwResult = ERROR_OUTOFMEMORY;
        goto Return_ExecuteCommandLine;
    }

	GetCommandDPathFromCommandLine(szCommandLine, cchWorkingDir, szWorkingDir, cchWorkingDir);

    //
    // run command line process
    if(!WIN::CreateProcess(NULL, szCommandLine, NULL, NULL, FALSE, CREATE_DEFAULT_ERROR_MODE, NULL, szWorkingDir, &sui, &pi))
    {
        // failed to launch.
        dwResult = GetLastError();
        goto Return_ExecuteCommandLine;
    }

	if (fWaitForProcess) {
		dwResult = WaitForProcess(pi.hProcess);
		if(ERROR_SUCCESS != dwResult)
			goto Return_ExecuteCommandLine;

	    WIN::GetExitCodeProcess(pi.hProcess, &dwResult);
	}

Return_ExecuteCommandLine:

    if (szWorkingDir)
        delete [] szWorkingDir;
    if (pi.hProcess)
        WIN::CloseHandle(pi.hProcess);
    if (pi.hThread)
        WIN::CloseHandle(pi.hThread);

    return dwResult;
}

/////////////////////////////////////////////////////////////////////////////
// ExecuteExeFile
//
DWORD ExecuteExeFile(LPSTR szExeFile, bool fWaitForProcess)
{
    DWORD dwResult = 0;

    //
    // build command line
    //  three acounts for terminating null plus quotes for module
    DWORD cchCommandLine = lstrlen(szExeFile) + 3;
    char *szCommandLine = new char[cchCommandLine];

    if (!szCommandLine)
    {
        dwResult = ERROR_OUTOFMEMORY;
        goto Return_ExecuteExeFile;
    }
    
    if (FAILED(StringCchCopy(szCommandLine, cchCommandLine, "\""))
        || FAILED(StringCchCat(szCommandLine, cchCommandLine, szExeFile))
        || FAILED(StringCchCat(szCommandLine, cchCommandLine, "\"")))
    {
        dwResult = ERROR_INSTALL_FAILURE;
        goto Return_ExecuteExeFile;
    }

	dwResult = ExecuteCommandLine(szCommandLine, fWaitForProcess);

Return_ExecuteExeFile:

    if (szCommandLine)
        delete [] szCommandLine;

    return dwResult;
}

/////////////////////////////////////////////////////////////////////////////
// CopyExecSetup
//
UINT CopyExecSetup(DWORD lcidLOCALE_INVARIANT, bool fWin9X, CDownloadUI *piDownloadUI, LPCSTR szModuleFile, DWORD dwModuleFileSize, LPCSTR szProductName)
{
    UINT  uiRet = 0;

    char szParentDirectory[MAX_PATH]    = {0};
    char szBaseDirectory[MAX_PATH]      = {0};
    char szCommonAppDataPath[MAX_PATH]  = {0};
    char szProductDataPath[MAX_PATH]    = {0};
    char szModuleFileC[MAX_PATH]        = {0};
    char szDataDirFile[MAX_PATH]        = {0};

	size_t cchBaseDirectorySize;

	SHFILEOPSTRUCT fileop;

	HANDLE hDataDirFile;
	DWORD NumberOfBytesWritten;

	GetDPathFromFPath(szModuleFile, dwModuleFileSize, szParentDirectory, MAX_PATH);
	GetDPathFromFPath(szParentDirectory, MAX_PATH, szBaseDirectory, MAX_PATH);
	if(FAILED(SHGetFolderPath(piDownloadUI->GetCurrentWindow(), (fWin9X ? CSIDL_APPDATA  : CSIDL_COMMON_APPDATA) | CSIDL_FLAG_CREATE, NULL, 0, szCommonAppDataPath)))
    {
        uiRet = GetLastError();
        goto CleanUp;
    }
    if (FAILED(StringCchCopy(szProductDataPath, MAX_PATH, szCommonAppDataPath)))
    {
        uiRet = ERROR_INSTALL_FAILURE;
        goto CleanUp;
    }
    if (FAILED(StringCchCat(szProductDataPath, MAX_PATH, szPathSep)))
    {
        uiRet = ERROR_INSTALL_FAILURE;
        goto CleanUp;
    }
    if (FAILED(StringCchCat(szProductDataPath, MAX_PATH, szProductName)))
    {
        uiRet = ERROR_INSTALL_FAILURE;
        goto CleanUp;
    }
	if (CompareString(lcidLOCALE_INVARIANT, NORM_IGNORECASE, szBaseDirectory, -1, szProductDataPath, -1) != CSTR_EQUAL)
	{
		if (GetFileAttributes(szProductDataPath) == -1)
			if (!CreateDirectory(szProductDataPath, NULL))
			{
				uiRet = GetLastError();
				goto CleanUp;
			}
		fileop.hwnd = piDownloadUI->GetCurrentWindow();
		fileop.wFunc = FO_COPY;
		fileop.pFrom = szParentDirectory;
		fileop.pTo = szProductDataPath;
		fileop.fFlags = FOF_NOCONFIRMATION | FOF_NOCONFIRMMKDIR;
		if (SHFileOperation(&fileop))
		{
			uiRet = GetLastError();
			goto CleanUp;
		}
		if (FAILED(StringCchCopy(szModuleFileC, MAX_PATH, szProductDataPath)))
		{
			uiRet = ERROR_INSTALL_FAILURE;
			goto CleanUp;
		}
		if (FAILED(StringCchCat(szModuleFileC, MAX_PATH, szPathSep)))
		{
			uiRet = ERROR_INSTALL_FAILURE;
			goto CleanUp;
		}
		if (FAILED(StringCchCat(szModuleFileC, MAX_PATH, GetFNameFromFPath(szParentDirectory, MAX_PATH))))
		{
			uiRet = ERROR_INSTALL_FAILURE;
			goto CleanUp;
		}
		if (FAILED(StringCchCat(szModuleFileC, MAX_PATH, szPathSep)))
		{
			uiRet = ERROR_INSTALL_FAILURE;
			goto CleanUp;
		}
		if (FAILED(StringCchCat(szModuleFileC, MAX_PATH, GetFNameFromFPath(szModuleFile, MAX_PATH))))
		{
			uiRet = ERROR_INSTALL_FAILURE;
			goto CleanUp;
		}
		if (FAILED(StringCchCopy(szDataDirFile, MAX_PATH, szProductDataPath)))
		{
			uiRet = ERROR_INSTALL_FAILURE;
			goto CleanUp;
		}
		if (FAILED(StringCchCat(szDataDirFile, MAX_PATH, szPathSep)))
		{
			uiRet = ERROR_INSTALL_FAILURE;
			goto CleanUp;
		}
		if (FAILED(StringCchCat(szDataDirFile, MAX_PATH, szDataDirFileName)))
		{
			uiRet = ERROR_INSTALL_FAILURE;
			goto CleanUp;
		}
		if (FAILED(StringCbLength(szBaseDirectory, MAX_PATH, &cchBaseDirectorySize)))
		{
			uiRet = ERROR_INSTALL_FAILURE;
			goto CleanUp;
		}
		if (INVALID_HANDLE_VALUE == (hDataDirFile = CreateFile(szDataDirFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)))
		{
			uiRet = GetLastError();
			goto CleanUp;
		}
		if (!WriteFile(hDataDirFile, szBaseDirectory, cchBaseDirectorySize + 1, &NumberOfBytesWritten, NULL))
		{
			uiRet = GetLastError();
			CloseHandle(hDataDirFile);
			goto CleanUp;
		}
		if (!CloseHandle(hDataDirFile))
		{
			uiRet = GetLastError();
			goto CleanUp;
		}
	    piDownloadUI->Terminate();
		ExecuteExeFile(szModuleFileC, true);
        uiRet = ERROR_INSTALL_SUSPEND;
	}

CleanUp:

    return uiRet;
}

/////////////////////////////////////////////////////////////////////////////
// IsMsiExist
//

bool IsMsiExist()
{
    char szSysMsiDll[MAX_PATH] = {0};
    char szSystemFolder[MAX_PATH] = {0};

    DWORD dwRet = WIN::GetSystemDirectory(szSystemFolder, MAX_PATH);
    if (0 == dwRet || MAX_PATH < dwRet)
        return false;

    if (FAILED(StringCchCopy(szSysMsiDll, sizeof(szSysMsiDll)/sizeof(szSysMsiDll[0]), szSystemFolder))
        || FAILED(StringCchCat(szSysMsiDll, sizeof(szSysMsiDll)/sizeof(szSysMsiDll[0]), "\\MSI.DLL")))
        return false;

    HINSTANCE hinstMsiSys = LoadLibrary(szSysMsiDll);
    if (0 == hinstMsiSys)
        return false;
    FreeLibrary(hinstMsiSys);

    return true;
}

/////////////////////////////////////////////////////////////////////////////
// GetSetupShortcutFileName
//
void GetSetupShortcutFileName(bool fWin9X, HWND hwndOwner, LPCSTR szProductName, LPSTR pszLink)
{
	const char szInstallOf[] = " のインストール";

	// スタートアップフォルダの取得
	SHGetFolderPath(hwndOwner, (fWin9X ? CSIDL_STARTUP : CSIDL_COMMON_STARTUP) | CSIDL_FLAG_CREATE, NULL, 0, pszLink);

	// ショートカットファイルのファイル名を作成
	StringCchCat(pszLink, MAX_PATH, szPathSep);
	StringCchCat(pszLink, MAX_PATH, szProductName);
	StringCchCat(pszLink, MAX_PATH, szInstallOf);
	StringCchCat(pszLink, MAX_PATH, szExtLnk);
}

/////////////////////////////////////////////////////////////////////////////
// GetUpdateManagerShortcutFileName
//
void GetUpdateManagerShortcutFileName(bool fWin9X, HWND hwndOwner, LPCSTR szProductName, LPSTR pszLink)
{
	const char szUpdateManager[] = " アップデートマネージャー";

	// スタートアップフォルダの取得
	SHGetFolderPath(hwndOwner, (fWin9X ? CSIDL_STARTUP : CSIDL_COMMON_STARTUP) | CSIDL_FLAG_CREATE, NULL, 0, pszLink);

	// ショートカットファイルのファイル名を作成
	StringCchCat(pszLink, MAX_PATH, szPathSep);
	StringCchCat(pszLink, MAX_PATH, szProductName);
	StringCchCat(pszLink, MAX_PATH, szUpdateManager);
	StringCchCat(pszLink, MAX_PATH, szExtLnk);
}

/////////////////////////////////////////////////////////////////////////////
// CreateShortcut
//
HRESULT CreateShortcut(
	LPSTR pszLink,                          // ショートカットの絶対パス
	LPSTR pszFile,                          // ターゲットファイル
	LPSTR pszDescription,                   // 説明
	LPSTR pszArgs,                          // 引数
	LPSTR pszWorkingDir,                    // 作業ディレクトリ
	LPSTR pszIconPath,                      // アイコンの場所
	int iIcon,                              // アイコンのインデックス
	int iShowCmd)                           // ウィンドウスタイル
{
	HRESULT hres;
	IShellLink *psl;

	// IShellLink オブジェクトを作成しポインタを取得する
	hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (void **)&psl);
	if (SUCCEEDED(hres))
	{
		IPersistFile *ppf;

		// ショートカットを二次記憶装置に保存するため IPersistFile
		// インターフェイスの問い合わせをおこなう
		hres = psl->QueryInterface(IID_IPersistFile, (void **)&ppf);
		if (SUCCEEDED(hres))
		{
			WORD wsz[MAX_PATH];  // Unicode 文字列へのバッファ

			psl->SetPath(pszFile);                      // ターゲットファイル
			psl->SetDescription(pszDescription);        // 説明
			psl->SetArguments(pszArgs);                 // 引数
			psl->SetWorkingDirectory(pszWorkingDir);    // 作業ディレクトリ
			psl->SetIconLocation(pszIconPath, iIcon);   // アイコン
			psl->SetShowCmd(iShowCmd);                  // ウィンドウスタイル

			// 文字列がANSI文字で構成されるようにする
			MultiByteToWideChar(CP_ACP, 0, pszLink, -1, (LPWSTR)wsz, MAX_PATH);

			// ショートカットを保存する
			hres = ppf->Save((LPCOLESTR)wsz, TRUE);

			// IPersistFile へのポインタを開放する
			ppf->Release();
		}
		// IShellLinkへのポインタを開放する
		psl->Release();
	}
	return hres;
}

/////////////////////////////////////////////////////////////////////////////
// CreateOldStartupShortcut
//
void CreateOldStartupShortcut(bool fWin9X, LPCSTR szModuleFile, DWORD dwModuleFileSize, HWND hwndOwner, LPCSTR szProductName, LPCSTR szExeName)
{
	const char szUpdateManagerDirPostfix[] = "999999b";
	const char szUpdateManagerExe[]        = "UpdateManager.exe";

	// スタートアップに登録
	TCHAR szModulePath[MAX_PATH];
	TCHAR pszLink[MAX_PATH];
	TCHAR szWorkingDir[MAX_PATH];
	TCHAR szDataDirFile[MAX_PATH];
	TCHAR szDataDir[MAX_PATH];
	HANDLE hDataDirFile;
	DWORD NumberOfBytesRead;

	// ショートカットファイルのファイル名を作成
	GetSetupShortcutFileName(fWin9X, hwndOwner, szProductName, pszLink);

	// 実行モジュールの作業ディレクトリの取得
	GetDPathFromFPath(szModuleFile, dwModuleFileSize, szWorkingDir, MAX_PATH);

	// スタートアップにショートカット作成
	if (SUCCEEDED(CoInitialize(NULL))) {
		CreateShortcut(pszLink, (LPSTR)szModuleFile, NULL, NULL, szWorkingDir);
		CoUninitialize();
	}

	// 実行モジュールのフルパスの取得
	GetDPathFromFPath(szWorkingDir, MAX_PATH, szDataDirFile, MAX_PATH);
	StringCchCat(szDataDirFile, MAX_PATH, szPathSep);
	StringCchCat(szDataDirFile, MAX_PATH, szDataDirFileName);
	if (INVALID_HANDLE_VALUE != (hDataDirFile = CreateFile(szDataDirFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL))) {
		ReadFile(hDataDirFile, szDataDir, MAX_PATH, &NumberOfBytesRead, NULL);
		CloseHandle(hDataDirFile);
	}
	StringCchCopy(szModulePath, MAX_PATH, szDataDir);
	StringCchCat(szModulePath, MAX_PATH, szPathSep);
	StringCchCat(szModulePath, MAX_PATH, szExeName);
	StringCchCat(szModulePath, MAX_PATH, szUpdateManagerDirPostfix);
	StringCchCat(szModulePath, MAX_PATH, szPathSep);
	StringCchCat(szModulePath, MAX_PATH, szExeName);
	StringCchCat(szModulePath, MAX_PATH, szUpdateManagerExe);

	if (GetFileAttributes(szModulePath) != -1) {
		// ショートカットファイルのファイル名を作成
		GetUpdateManagerShortcutFileName(fWin9X, hwndOwner, szProductName, pszLink);

		// 実行モジュールの作業ディレクトリの取得
		GetDPathFromFPath(szModulePath, MAX_PATH, szWorkingDir, MAX_PATH);

		// スタートアップにショートカット作成
		if (SUCCEEDED(CoInitialize(NULL))) {
			CreateShortcut(pszLink, szModulePath, NULL, NULL, szWorkingDir);
			CoUninitialize();
		}
	}
}

/////////////////////////////////////////////////////////////////////////////
// DeleteOldStartupShortcut
//
void DeleteOldStartupShortcut(bool fWin9X, HWND hwndOwner, LPCSTR szProductName)
{
	TCHAR pszLink[MAX_PATH];

	GetSetupShortcutFileName(fWin9X, hwndOwner, szProductName, pszLink);
	DeleteFile(pszLink);

	GetUpdateManagerShortcutFileName(fWin9X, hwndOwner, szProductName, pszLink);
	DeleteFile(pszLink);
}

/////////////////////////////////////////////////////////////////////////////
// SetAbsoluteForegroundWindow
//

#ifndef SPI_GETFOREGROUNDLOCKTIMEOUT
#define SPI_GETFOREGROUNDLOCKTIMEOUT        0x2000
#endif
#ifndef SPI_SETFOREGROUNDLOCKTIMEOUT
#define SPI_SETFOREGROUNDLOCKTIMEOUT        0x2001
#endif

void SetAbsoluteForegroundWindow(HWND hWnd)
{
	SetForegroundWindow(hWnd);

	int nTargetID, nForegroundID;
	DWORD sp_time;

	// フォアグラウンドウィンドウを作成したスレッドのIDを取得
	nForegroundID = GetWindowThreadProcessId(GetForegroundWindow(), NULL);
	// 目的のウィンドウを作成したスレッドのIDを取得
	nTargetID = GetWindowThreadProcessId(hWnd, NULL );

	// スレッドのインプット状態を結び付ける
	AttachThreadInput(nTargetID, nForegroundID, TRUE );  // TRUE で結び付け

	// 現在の設定を sp_time に保存
	SystemParametersInfo( SPI_GETFOREGROUNDLOCKTIMEOUT,0,&sp_time,0);
	// ウィンドウの切り替え時間を 0ms にする
	SystemParametersInfo( SPI_SETFOREGROUNDLOCKTIMEOUT,0,(LPVOID)0,0);

	// ウィンドウをフォアグラウンドに持ってくる
	SetForegroundWindow(hWnd);

	// 設定を元に戻す
	SystemParametersInfo( SPI_SETFOREGROUNDLOCKTIMEOUT,0,(LPVOID)sp_time,0);

	// スレッドのインプット状態を切り離す
	AttachThreadInput(nTargetID, nForegroundID, FALSE );  // FALSE で切り離し
}

/////////////////////////////////////////////////////////////////////////////
// PumpWaitingMessages
//
void PumpWaitingMessages()
{
	MSG msg;
	while (::PeekMessage(&msg, NULL, 0, 0, PM_NOREMOVE)) {
		if (msg.message == WM_QUIT)
			break;
		::PeekMessage(&msg, NULL, 0, 0, PM_REMOVE);
		::TranslateMessage(&msg);
		::DispatchMessage (&msg);
	}
}

/////////////////////////////////////////////////////////////////////////////
// EnumThreadWndProc
//

const char *szThreadWindowText;
HWND hwndThread;

BOOL CALLBACK EnumThreadWndProc(HWND hwnd, LPARAM lParam)
{
	const char szSpcVerDot[] = " Ver.";
	DWORD dwSpcVerDotSize = 5;

	BOOL bRv = TRUE;

	if (GetWindow(hwnd, GW_OWNER) == NULL) {
		int nWindowTextLen = GetWindowTextLength(hwnd);
		if (nWindowTextLen) {
			char* szWindowText = new char[nWindowTextLen + 1];
			if (szWindowText) {
				if (GetWindowText(hwnd, szWindowText, nWindowTextLen + 1)) {
					size_t cchThreadWindowTextSize;
					if (SUCCEEDED(StringCchLength(szThreadWindowText, 256, &cchThreadWindowTextSize))) {
						DWORD dwThreadWindowTextCSize = cchThreadWindowTextSize + dwSpcVerDotSize;
						char *szThreadWindowTextC = new char[dwThreadWindowTextCSize + 1];
						if (szThreadWindowTextC) {
							if (
								SUCCEEDED(StringCchCopy(szThreadWindowTextC, dwThreadWindowTextCSize + 1, szThreadWindowText))
								&& SUCCEEDED(StringCchCat(szThreadWindowTextC, dwThreadWindowTextCSize + 1, szSpcVerDot))
							) {
								if (nWindowTextLen > (int)dwThreadWindowTextCSize)
									szWindowText[dwThreadWindowTextCSize] = '\0';
								DWORD lcid = MAKELCID(MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), SORT_DEFAULT);
								if (CompareString(lcid, 0, szWindowText, -1, szThreadWindowTextC, -1) == CSTR_EQUAL) {
									hwndThread = hwnd;
									bRv = FALSE;
								}
							}
							delete [] szThreadWindowTextC;
						}
					}
				}
				delete [] szWindowText;
			}
		}
	}

	return bRv;
}

/////////////////////////////////////////////////////////////////////////////
// TerminateProduct
//
void TerminateProduct(DWORD lcidLOCALE_INVARIANT, bool fWin9X, HINSTANCE hInst, HWND hwndOwner, LPCSTR szTitle, LPCSTR szProductName, LPCSTR szExeName)
{
	char *szProductFileName = new char[MAX_PATH];
	if (szProductFileName) {
		if (
			SUCCEEDED(StringCchCopy(szProductFileName, MAX_PATH, szExeName))
			&& SUCCEEDED(StringCchCat(szProductFileName, MAX_PATH, szExtExe))
		) {
			HANDLE hSnapshot;
			PROCESSENTRY32 pe;
			char *szExeFileName;
			BOOL bProcessFound = FALSE;
			if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) != (HANDLE)-1) {
				pe.dwSize = sizeof(PROCESSENTRY32);
				if (Process32First(hSnapshot, &pe))
					do {
						szExeFileName = (char *)(fWin9X ? GetFNameFromFPath(pe.szExeFile, MAX_PATH) : pe.szExeFile);
						if (CompareString(lcidLOCALE_INVARIANT, NORM_IGNORECASE, szExeFileName, -1, szProductFileName, -1) == CSTR_EQUAL) {
							bProcessFound = TRUE;
							break;
						}
					} while (Process32Next(hSnapshot, &pe));
				CloseHandle(hSnapshot);
			}
			if (bProcessFound) {
				char szMessage[MAX_STR_LENGTH]  = {0};
				char szFormat[MAX_STR_LENGTH] = {0};

				WIN::LoadString(hInst, IDS_TERMINATE_PRODUCT, szFormat, sizeof(szFormat)/sizeof(char));
				StringCchPrintf(szMessage, sizeof(szMessage), szFormat, szProductName);
				MessageBox(hwndOwner, szMessage, szTitle, MB_OK | MB_ICONINFORMATION);

				if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0)) != (HANDLE)-1) {
					pe.dwSize = sizeof(PROCESSENTRY32);
					if (Process32First(hSnapshot, &pe)) {
						THREADENTRY32 te;
						do {
							szExeFileName = (char *)(fWin9X ? GetFNameFromFPath(pe.szExeFile, MAX_PATH) : pe.szExeFile);
							if (CompareString(lcidLOCALE_INVARIANT, NORM_IGNORECASE, szExeFileName, -1, szProductFileName, -1) == CSTR_EQUAL) {
								te.dwSize = sizeof(THREADENTRY32);
								if (Thread32First(hSnapshot, &te))
									do {
										if (te.th32OwnerProcessID == pe.th32ProcessID) {
											szThreadWindowText = szProductName;
											hwndThread = 0;
											EnumThreadWindows(te.th32ThreadID, EnumThreadWndProc, 0);
											if (hwndThread) {
												ShowWindow(hwndThread, SW_SHOW);
												SetAbsoluteForegroundWindow(hwndThread);
												int nWindowTextLen = GetWindowTextLength(hwndThread);
												char* szWindowText = new char[nWindowTextLen + 1];
												if (szWindowText) {
													if (GetWindowText(hwndThread, szWindowText, nWindowTextLen + 1))
														while (1) {
															PostMessage(hwndThread, WM_QUIT, 0, 0);
															PumpWaitingMessages();
															if (FindWindow(NULL, szWindowText) == NULL)
																break;
															Sleep(100);
														}
													delete [] szWindowText;
												}
												break;
											}
										}
									} while (Thread32Next(hSnapshot, &te));
							}
						} while (Process32Next(hSnapshot, &pe));
					}
					CloseHandle(hSnapshot);
				}
			}
		}
		delete [] szProductFileName;
	}
}

/////////////////////////////////////////////////////////////////////////////
// ExecuteProduct
//
void ExecuteProduct(LPCSTR szProductCode, LPCSTR szExeName)
{
	const char szUninstallKey[]         = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
	const char szInstallLocationValue[] = "InstallLocation";

	char *szKey = new char[MAX_PATH];
	if (szKey) {
		if (
			SUCCEEDED(StringCchCopy(szKey, MAX_PATH, szUninstallKey))
			&& SUCCEEDED(StringCchCat(szKey, MAX_PATH, szProductCode))
		) {
			DWORD dwSize = 0;
			HKEY  hKey = 0;
			DWORD dwType = 0;
			if (
				ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKey, 0, KEY_READ, &hKey)
				&& ERROR_SUCCESS == RegQueryValueEx(hKey, szInstallLocationValue, NULL, &dwType, NULL, &dwSize)
				&& dwSize > 0
				&& REG_SZ == dwType
			) {
				char *szInstallLocation = new char[dwSize];
				if (szInstallLocation) {
					if (ERROR_SUCCESS == RegQueryValueEx(hKey, szInstallLocationValue, NULL, &dwType, (LPBYTE)szInstallLocation, &dwSize)) {
						char *szProductFile = new char[MAX_PATH];
						if (szProductFile) {
							if (
								SUCCEEDED(StringCchCopy(szProductFile, MAX_PATH, szInstallLocation))
								&& SUCCEEDED(StringCchCat(szProductFile, MAX_PATH, szExeName))
								&& SUCCEEDED(StringCchCat(szProductFile, MAX_PATH, szExtExe))
							)
								ExecuteExeFile(szProductFile, false);
							delete [] szProductFile;
						}
					}
					delete [] szInstallLocation;
				}
			}
			if (hKey)
				RegCloseKey(hKey);
		}
		delete [] szKey;
	}
}

/////////////////////////////////////////////////////////////////////////////
// IsRebootNecessary
//
bool IsRebootNecessary(bool fWin9X)
{
	const char szSessionManagerKey[]                = "SYSTEM\\CurrentControlSet\\Control\\Session Manager";
	const char szPendingFileRenameOperationsValue[] = "PendingFileRenameOperations";

	const char szWinInitIni[] = "Wininit.ini";

	bool fRv = false;

	if (fWin9X) {
		char *szWinInitIniFilePath = new char[MAX_PATH];
		if (szWinInitIniFilePath) {
			if (
				GetWindowsDirectory(szWinInitIniFilePath, MAX_PATH)
				&& SUCCEEDED(StringCchCat(szWinInitIniFilePath, MAX_PATH, szPathSep))
				&& SUCCEEDED(StringCchCat(szWinInitIniFilePath, MAX_PATH, szWinInitIni))
			)
				if (GetFileAttributes(szWinInitIniFilePath) != -1)
					fRv = true;
			delete [] szWinInitIniFilePath;
		}
	} else {
		DWORD dwSize = 0;
		HKEY  hKey = 0;
		DWORD dwType = 0;

		if (
			ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE, szSessionManagerKey, 0, KEY_READ, &hKey)
			&& ERROR_SUCCESS == RegQueryValueEx(hKey, szPendingFileRenameOperationsValue, NULL, &dwType, NULL, &dwSize)
		) {
			fRv = true;
			RegCloseKey(hKey);
		}
	}

	return fRv;
}

/////////////////////////////////////////////////////////////////////////////
// UninstallOldProduct
//
UINT UninstallOldProduct(bool fWin9X, LPCSTR szModuleFile, DWORD dwModuleFileSize, HINSTANCE hInst, HWND hwndOwner, LPCSTR szTitle, LPCSTR szProductName, LPCSTR szExeName)
{
	const char szUninstallKey[]         = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
	const char szUninstallStringValue[] = "UninstallString";

	int uiRet = ERROR_SUCCESS;

	char *szKey = new char[MAX_PATH];
	if (szKey) {
		if (
			SUCCEEDED(StringCchCopy(szKey, MAX_PATH, szUninstallKey))
			&& SUCCEEDED(StringCchCat(szKey, MAX_PATH, szProductName))
		) {
			DWORD dwSize = 0;
			HKEY  hKey = 0;
			DWORD dwType = 0;
			char *szUninstallString = 0;
			if (
				ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKey, 0, KEY_READ, &hKey)
				&& ERROR_SUCCESS == RegQueryValueEx(hKey, szUninstallStringValue, NULL, &dwType, NULL, &dwSize)
				&& dwSize > 0
				&& REG_SZ == dwType
			) {
				szUninstallString = new char[dwSize];
				if (szUninstallString) {
					*szUninstallString = 0;
					RegQueryValueEx(hKey, szUninstallStringValue, NULL, &dwType, (LPBYTE)szUninstallString, &dwSize);
				}
			}
			if (hKey)
				RegCloseKey(hKey);
			if (szUninstallString) {
				if (*szUninstallString) {
					char szMessage[MAX_STR_LENGTH]  = {0};
					char szFormat[MAX_STR_LENGTH] = {0};

					WIN::LoadString(hInst, IDS_UNINSTALL_OLDPRODUCT, szFormat, sizeof(szFormat)/sizeof(char));
					StringCchPrintf(szMessage, sizeof(szMessage), szFormat, szProductName);
					MessageBox(hwndOwner, szMessage, szTitle, MB_OK | MB_ICONINFORMATION);

					if (ERROR_SUCCESS == ExecuteCommandLine(szUninstallString, true))
						if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKey, 0, KEY_READ, &hKey)) {
							uiRet = ERROR_INSTALL_USEREXIT;
							RegCloseKey(hKey);
						} else
							if (IsRebootNecessary(fWin9X)) {
								uiRet = ERROR_INSTALL_SUSPEND;
								CreateOldStartupShortcut(fWin9X, szModuleFile, dwModuleFileSize, hwndOwner, szProductName, szExeName);
							}
				}
				delete [] szUninstallString;
			}
		}
		delete [] szKey;
	}

	return uiRet;
}

/////////////////////////////////////////////////////////////////////////////
// DeleteDataDirFile
//

void DeleteDataDirFile(LPCSTR szModuleFile, DWORD dwModuleFileSize)
{
	char szParentDirectory[MAX_PATH];
	char szDataDirFile[MAX_PATH];

	GetDPathFromFPath(szModuleFile, dwModuleFileSize, szParentDirectory, MAX_PATH);
	GetDPathFromFPath(szParentDirectory, MAX_PATH, szDataDirFile, MAX_PATH);
	StringCchCat(szDataDirFile, MAX_PATH, szPathSep);
	StringCchCat(szDataDirFile, MAX_PATH, szDataDirFileName);

	DeleteFile(szDataDirFile);
}

/////////////////////////////////////////////////////////////////////////////
// IsJetUpgradeNecessary
//

bool IsJetUpgradeNecessary(int iMajorVersion, HWND hwndOwner)
{
	const char szMsjetFileName[] = "msjet40.dll";
	const char szDaoFilePath[]   = "Microsoft Shared\\DAO\\dao360.dll";

    char szMsjetFile[MAX_PATH] = {0};
    char szDaoFile[MAX_PATH]   = {0};

    if (WIN::GetSystemDirectory(szMsjetFile, MAX_PATH) == 0)
		return true;

	if (
		FAILED(StringCchCat(szMsjetFile, MAX_PATH, szPathSep))
		|| FAILED(StringCchCat(szMsjetFile, MAX_PATH, szMsjetFileName))
	)
		return true;

	DWORD dwLSVer;
	DWORD dwRet;

	dwRet = GetFileVersionNumber(szMsjetFile, NULL, &dwLSVer);
	if (ERROR_SUCCESS == dwRet && HIWORD(dwLSVer) < (iMajorVersion == 4 ? 8015 : 8618) || ERROR_FILE_NOT_FOUND == dwRet)
		return true;

	if(FAILED(SHGetFolderPath(hwndOwner, CSIDL_PROGRAM_FILES_COMMON, NULL, 0, szDaoFile)))
		return true;

	if (
		FAILED(StringCchCat(szDaoFile, MAX_PATH, szPathSep))
		|| FAILED(StringCchCat(szDaoFile, MAX_PATH, szDaoFilePath))
	)
		return true;

	dwRet = GetFileVersionNumber(szDaoFile, NULL, &dwLSVer);
	if (ERROR_SUCCESS == dwRet && HIWORD(dwLSVer) < (iMajorVersion == 4 ? 8025 : 8618) || ERROR_FILE_NOT_FOUND == dwRet)
		return true;

	return false;
}

/////////////////////////////////////////////////////////////////////////////
// DownloadAndUpgradeJet
//
UINT DownloadAndUpgradeJet(bool fWin9X, int iMajorVersion, int iMinorVersion, HINSTANCE hInst, CDownloadUI *piDownloadUI, LPCSTR szAppTitle, LPCSTR szUpdateLocation)
{
	LPCSTR szUpdate;

    char szUserPrompt[MAX_STR_LENGTH] = {0};

	char *szTempPath         = 0;
	char *szUpdatePath       = 0;
	char *szUpdateCacheFile  = 0;
	const char *pch          = 0;

	DWORD cchTempPath         = 0;
	DWORD cchUpdatePath       = 0;
	DWORD cchUpdateCacheFile  = 0;
	DWORD dwLastError         = 0;
    UINT  uiRet               = 0;
	HRESULT hr                = 0;

	char szText[MAX_STR_CAPTION] = {0};

	if (!IsJetUpgradeNecessary(iMajorVersion, piDownloadUI->GetCurrentWindow()))
		goto CleanUp;

	switch (iMajorVersion) {
	case 4:
		switch (iMinorVersion) {
		case 0:
		case 10:
			szUpdate = szUpdateJet9xNt;
			break;
		case 90:
			szUpdate = szUpdateJetMe;
			break;
		default:
			goto CleanUp;
		}
		break;
	case 5:
		switch (iMinorVersion) {
		case 0:
			switch (GetKeyboardType(1)) {
			case 0xD01:
			case 0xD02:
			case 0xD03:
			case 0xD04:
				szUpdate = szUpdateJet2000NEC98;
				break;
			default:
				szUpdate = szUpdateJet2000;
			}
			break;
		case 1:
			szUpdate = szUpdateJetXp;
			break;
		case 2:
			szUpdate = szUpdateJet2003;
			break;
		default:
			goto CleanUp;
		}
		break;
	default:
		goto CleanUp;
	}

    // Ask the user if they want to upgrade the Jet
    WIN::LoadString(hInst, IDS_ALLOW_JET_UPDATE, szUserPrompt, MAX_STR_LENGTH);
    if (IDYES != WIN::MessageBox(piDownloadUI->GetCurrentWindow(), szUserPrompt, szAppTitle, MB_YESNO|MB_ICONQUESTION))
    {
        // user decided to cancel
        ReportUserCancelled(hInst, piDownloadUI->GetCurrentWindow(), szAppTitle);
        uiRet = ERROR_INSTALL_USEREXIT;
        goto CleanUp;
    }

	// generate the path to the update == UPDATELOCATION + szUpdate
	//   note: szUpdate is a relative path
	cchTempPath = lstrlen(szUpdateLocation) + lstrlen(szUpdate) + 2; // 1 for slash, 1 for null
	szTempPath = new char[cchTempPath];
	if (!szTempPath)
	{
		ReportErrorOutOfMemory(hInst, piDownloadUI->GetCurrentWindow(), szAppTitle);
		uiRet = ERROR_OUTOFMEMORY;
		goto CleanUp;
	}
	memset((void*)szTempPath, 0x0, cchTempPath*sizeof(char));
	hr = StringCchCopy(szTempPath, cchTempPath, szUpdateLocation);
	if (FAILED(hr))
	{
		uiRet = HRESULT_CODE(hr);
		PostFormattedError(hInst, piDownloadUI->GetCurrentWindow(), szAppTitle, IDS_INVALID_PATH, szTempPath);
		goto CleanUp;
	}

	// check for trailing slash on szUpdateLocation
	pch = szUpdateLocation + lstrlen(szUpdateLocation) + 1; // put at null terminator
	pch = CharPrev(szUpdateLocation, pch);
	if (*pch != '/')
	{
		hr = StringCchCat(szTempPath, cchTempPath, szUrlPathSep);
		if (FAILED(hr))
		{
			uiRet = HRESULT_CODE(hr);
			PostFormattedError(hInst, piDownloadUI->GetCurrentWindow(), szAppTitle, IDS_INVALID_PATH, szTempPath);
			goto CleanUp;
		}
	}

	hr = StringCchCat(szTempPath, cchTempPath, szUpdate);
	if (FAILED(hr))
	{
		uiRet = HRESULT_CODE(hr);
		PostFormattedError(hInst, piDownloadUI->GetCurrentWindow(), szAppTitle, IDS_INVALID_PATH, szTempPath);
		goto CleanUp;
	}

	// canonicalize the URL path
	cchUpdatePath = cchTempPath*2;
	szUpdatePath = new char[cchUpdatePath];
	if (!szUpdatePath)
	{
		ReportErrorOutOfMemory(hInst, piDownloadUI->GetCurrentWindow(), szAppTitle);
		uiRet = ERROR_OUTOFMEMORY;
		goto CleanUp;
	}

	if (!InternetCanonicalizeUrl(szTempPath, szUpdatePath, &cchUpdatePath, 0))
	{
		dwLastError = GetLastError();
		if (ERROR_INSUFFICIENT_BUFFER == dwLastError)
		{
			// try again
			delete [] szUpdatePath;
			szUpdatePath = new char[cchUpdatePath];
			if (!szUpdatePath)
			{
				ReportErrorOutOfMemory(hInst, piDownloadUI->GetCurrentWindow(), szAppTitle);
				uiRet = ERROR_OUTOFMEMORY;
				goto CleanUp;
			}
			dwLastError = 0; // reset to success for 2nd attempt
			if (!InternetCanonicalizeUrl(szTempPath, szUpdatePath, &cchUpdatePath, 0))
				dwLastError = GetLastError();
		}
	}
	if (0 != dwLastError)
	{
		// error -- invalid path/Url
		PostFormattedError(hInst, piDownloadUI->GetCurrentWindow(), szAppTitle, IDS_INVALID_PATH, szTempPath);
		uiRet = dwLastError;
		goto CleanUp;
	}

	// set action text for download
	WIN::LoadString(hInst, IDS_DOWNLOADING_JET, szText, MAX_STR_CAPTION);
	if (irmCancel == piDownloadUI->SetActionText(szText))
	{
		ReportUserCancelled(hInst, piDownloadUI->GetCurrentWindow(), szAppTitle);
		uiRet = ERROR_INSTALL_USEREXIT;
		goto CleanUp;
	}

	// download the Update file so we can run it -- must be local to execute
	szUpdateCacheFile = new char[MAX_PATH];
	cchUpdateCacheFile = MAX_PATH;
	if (!szUpdateCacheFile)
	{
		ReportErrorOutOfMemory(hInst, piDownloadUI->GetCurrentWindow(), szAppTitle);
		uiRet = ERROR_OUTOFMEMORY;
		goto CleanUp;
	}

	hr = WIN::URLDownloadToCacheFile(NULL, szUpdatePath, szUpdateCacheFile, cchUpdateCacheFile, 0, /* IBindStatusCallback = */ &CDownloadBindStatusCallback(piDownloadUI));
	if (piDownloadUI->HasUserCanceled())
	{
		ReportUserCancelled(hInst, piDownloadUI->GetCurrentWindow(), szAppTitle);
		uiRet = ERROR_INSTALL_USEREXIT;
		goto CleanUp;
	}
	if (FAILED(hr))
	{
		// error during download -- probably because file not found (or lost connection)
		PostFormattedError(hInst, piDownloadUI->GetCurrentWindow(), szAppTitle, IDS_NOJET, szUpdatePath);
		uiRet = ERROR_FILE_NOT_FOUND;
		goto CleanUp;
	}

    uiRet = ExecuteExeFile(szUpdateCacheFile, true);

	if (IsRebootNecessary(fWin9X))
		uiRet = ERROR_INSTALL_SUSPEND;
	else if (IsJetUpgradeNecessary(iMajorVersion, piDownloadUI->GetCurrentWindow())) {
		ReportUserCancelled(hInst, piDownloadUI->GetCurrentWindow(), szAppTitle);
		uiRet = ERROR_INSTALL_USEREXIT;
	}

CleanUp:
	if (szTempPath)
		delete [] szTempPath;
	if (szUpdatePath)
		delete [] szUpdatePath;
	if (szUpdateCacheFile)
	{
		WIN::DeleteUrlCacheEntry(szUpdateCacheFile);
		delete [] szUpdateCacheFile;
	}

    return uiRet;
}
