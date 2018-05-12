//+-------------------------------------------------------------------------
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
//  File:       setup.h
//
//--------------------------------------------------------------------------

#ifndef __SETUP_H_58FA8147_50A0_4FDC_BD83_17C3A2525E0A_
#define __SETUP_H_58FA8147_50A0_4FDC_BD83_17C3A2525E0A_

#include "setupui.h"

#include <windows.h>
#include <wincrypt.h>

/*--------------------------------------------------------------------------
 *
 * Constants
 *
 --------------------------------------------------------------------------*/
#define MAX_STR_LENGTH 1024
#define MINIMUM_SUPPORTED_MSI_VERSION 150
#define MAX_LENGTH_GUID 40

const char szUrlPathSep[] = "/";
const char szPathSep[] = "\\";

const char szDefaultOperation[] = "DEFAULT";
const char szInstallOperation[] = "INSTALL";
const char szMinPatchOperation[] = "MINPATCH";
const char szMajPatchOperation[] = "MAJPATCH";
const char szInstallUpdOperation[] = "INSTALLUPD";

const char szDefaultMinPatchCommandLine[] = "REINSTALL=ALL REINSTALLMODE=omus";
const char szDefaultInstallUpdCommandLine[] = "REINSTALL=ALL REINSTALLMODE=vomus";
const char szAdminInstallProperty[] = " ACTION=ADMIN";

const char sqlProductCode[] = "SELECT `Value` FROM `Property` WHERE `Property`='ProductCode'";

const char szExtExe[] = ".exe";
const char szExtLnk[] = ".lnk";
const char szDataDirFileName[] = "DataDir.txt";
const char szUpdateJet9xNt[] = "jet40sp8_9xnt.exe";
const char szUpdateJetMe[] = "jet40sp8_wme.exe";
const char szUpdateJet2000[] = "Windows2000-KB837001-x86-JPN.EXE";
const char szUpdateJet2000NEC98[] = "Windows2000-KB837001-NEC98-JPN.EXE";
const char szUpdateJetXp[] = "WindowsXP-KB837001-x86-JPN.EXE";
const char szUpdateJet2003[] = "WindowsServer2003-KB837001-x86-JPN.EXE";

/*--------------------------------------------------------------------------
 *
 * Enums
 *
 --------------------------------------------------------------------------*/
enum itvEnum
{
    itvWintrustNotOnMachine = 0,
    itvTrusted = 1,
    itvUnTrusted = 2
};

// Execution modes.
enum emEnum
{
    emPreset = 0,
    emHelp = 1,
    emVerify = 2,
    emAdminInstall = 3
};

/*--------------------------------------------------------------------------
 *
 * Prototypes
 *
 --------------------------------------------------------------------------*/

DWORD VerifyFileSignature (LPCSTR lpszModule, __in_opt LPSTR lpszCmdLine);
emEnum GetExecutionMode (LPCSTR lpszCmdLine);
DWORD GetNextArgument (LPCSTR pszCmdLine, LPCSTR *ppszArgStart, LPCSTR *ppszArgEnd, bool * pfQuoted);
DWORD GetAdminInstallInfo (bool fPatch, __in_opt LPSTR lpszCmdLine, LPCSTR * ppszAdminImagePath);
//bool AlreadyInProgress(HANDLE& hMutex);
bool AlreadyInProgress(bool fWin9X, int iMajorVersion, HANDLE& hMutex);
void DisplayUsage (HINSTANCE hInst, HWND hwndOwner, LPCSTR szCaption);
DWORD GetFileVersionNumber(__in LPSTR szFilename, DWORD *pdwMSVer, DWORD *pdwLSVer);
bool IsOSWin9X(int *piMajVer, int *piMinVer);
//bool IsAdmin();
bool IsAdmin(bool fWin9X, int iMajorVersion);
bool IsTerminalServerInstalled(bool fWin9X, int iMajorVersion);
bool IsOSSupported();
bool AcquireShutdownPrivilege();

LPCSTR GetFNameFromFPath(LPCSTR szFPath, size_t cchMax);
void GetDPathFromFPath(LPCSTR szFPath, size_t cchMaxFPath, LPSTR szDPath, size_t cchMaxDPath);
void GetCommandDPathFromCommandLine(LPCSTR szCommandLine, size_t cchMaxCommandLine, LPSTR szCommandDPath, size_t cchMaxCommandDPath);
DWORD ExecuteCommandLine(LPSTR szCommandLine, bool fWaitForProcess);
DWORD ExecuteExeFile(LPSTR szExeFile, bool fWaitForProcess);
UINT CopyExecSetup(DWORD lcidLOCALE_INVARIANT, bool fWin9X, CDownloadUI *piDownloadUI, LPCSTR szModuleFile, DWORD dwModuleFileSize, LPCSTR szProductName);
bool IsMsiExist();
void GetSetupShortcutFileName(bool fWin9X, HWND hwndOwner, LPCSTR szProductName, LPSTR pszLink);
void GetUpdateManagerShortcutFileName(bool fWin9X, HWND hwndOwner, LPCSTR szProductName, LPSTR pszLink);
HRESULT CreateShortcut(
	LPSTR pszLink,                          // �V���[�g�J�b�g�̐�΃p�X
	LPSTR pszFile,                          // �^�[�Q�b�g�t�@�C��
	LPSTR pszDescription = NULL,            // ����
	LPSTR pszArgs        = NULL,            // ����
	LPSTR pszWorkingDir  = NULL,            // ��ƃf�B���N�g��
	LPSTR pszIconPath    = NULL,            // �A�C�R���̏ꏊ
	int iIcon            = 0,               // �A�C�R���̃C���f�b�N�X
	int iShowCmd         = SW_SHOWNORMAL);  // �E�B���h�E�X�^�C��
void CreateOldStartupShortcut(bool fWin9X, LPCSTR szModuleFile, DWORD dwModuleFileSize, HWND hwndOwner, LPCSTR szProductName, LPCSTR szExeName);
void DeleteOldStartupShortcut(bool fWin9X, HWND hwndOwner, LPCSTR szProductName);
void SetAbsoluteForegroundWindow(HWND hWnd);
void PumpWaitingMessages();
BOOL CALLBACK EnumThreadWndProc(HWND hwnd, LPARAM lParam);
void TerminateProduct(DWORD lcidLOCALE_INVARIANT, bool fWin9X, HINSTANCE hInst, HWND hwndOwner, LPCSTR szTitle, LPCSTR szProductName, LPCSTR szExeName);
void ExecuteProduct(LPCSTR szProductCode, LPCSTR szExeName);
bool IsRebootNecessary(bool fWin9X);
UINT UninstallOldProduct(bool fWin9X, LPCSTR szModuleFile, DWORD dwModuleFileSize, HINSTANCE hInst, HWND hwndOwner, LPCSTR szTitle, LPCSTR szProductName, LPCSTR szExeName);
void DeleteDataDirFile(LPCSTR szModuleFile, DWORD dwModuleFileSize);
bool IsJetUpgradeNecessary(int iMajorVersion, HWND hwndOwner);
UINT DownloadAndUpgradeJet(bool fWin9X, int iMajorVersion, int iMinorVersion, HINSTANCE hInst, CDownloadUI *piDownloadUI, LPCSTR szAppTitle, LPCSTR szUpdateLocation);

/////////////////////////////////////////////////////////////////////////////
//
// WinVerifyTrust functions
//
/////////////////////////////////////////////////////////////////////////////
itvEnum IsPackageTrusted(LPCSTR szSetupEXE, LPCSTR szPackage, HWND hwndParent);
itvEnum IsFileTrusted(LPCWSTR szwFile, HWND hwndParent, DWORD dwUIChoice, bool *pfIsSigned, PCCERT_CONTEXT *ppcSigner);

/////////////////////////////////////////////////////////////////////////////
//
// Upgrade functions
//
/////////////////////////////////////////////////////////////////////////////
bool IsMsiUpgradeNecessary(ULONG ulReqMsiMinVer);
DWORD ExecuteUpgradeMsi(__in LPSTR szUpgradeMsi);
DWORD ExecuteVerifyUpdate(LPCSTR szModuleFile, LPCSTR szUpdateCachePath);
DWORD WaitForProcess(HANDLE handle);
bool IsUpdateRequiredVersion(__in LPSTR szFilename, ULONG ulMinVer);
UINT UpgradeMsi(HINSTANCE hInst, CDownloadUI *piDownloadUI, LPCSTR szAppTitle, LPCSTR szUpgdLocation, LPCSTR szUpgrade, ULONG ulMinVer);
UINT DownloadAndUpgradeMsi(HINSTANCE hInst, CDownloadUI *piDownloadUI, LPCSTR szAppTitle, LPCSTR szBase, LPCSTR szUpdate, LPCSTR szModuleFile, ULONG ulMinVer);
UINT ValidateUpdate(HINSTANCE hInst, CDownloadUI *piDownloadUI, LPCSTR szAppTitle, __in LPSTR szUpdatePath, LPCSTR szModuleFile, ULONG ulMinVer);

/////////////////////////////////////////////////////////////////////////////
//
// Error handling functions
//
/////////////////////////////////////////////////////////////////////////////
void ReportErrorOutOfMemory(HINSTANCE hInst, HWND hwndOwner, LPCSTR szCaption);
void PostResourceNotFoundError(HINSTANCE hInst, HWND hwndOwner, LPCSTR szTitle, LPCSTR szName);
void ReportUserCancelled(HINSTANCE hInst, HWND hwndOwner, LPCSTR szTitle);
void PostError(HINSTANCE hInst, HWND hwndOwner, LPCSTR szTitle, UINT uiErrorId);
void PostError(HINSTANCE hInst, HWND hwndOwner, LPCSTR szTitle, UINT uiErrorId, int iValue);
void PostError(HINSTANCE hInst, HWND hwndOwner, LPCSTR szTitle, UINT uiErrorId, LPCSTR szValue);
void PostError(HINSTANCE hInst, HWND hwndOwner, LPCSTR szTitle, UINT uiErrorId, LPCSTR szValue, int iValue);
void PostMsiError(HINSTANCE hInst, HINSTANCE hMsi, HWND hwndOwner, LPCSTR szTitle, UINT uiErrorId);
void PostFormattedError(HINSTANCE hInst, HWND hwndOwner, LPCSTR szTitle, UINT uiErrorId, LPCSTR szValue);

/////////////////////////////////////////////////////////////////////////////
//
// Update command line options
//
//
/////////////////////////////////////////////////////////////////////////////
//const char szDelayReboot[] = " /norestart";
//const char szDelayRebootQuiet[] = " /quiet /norestart";
const char szDelayReboot[] = " /c:\"msiinst /delayreboot\"";
const char szDelayRebootQuiet[] = " /c:\"msiinst /delayrebootq\"";

/////////////////////////////////////////////////////////////////////////////
//
// Debugging Functions
//
//
/////////////////////////////////////////////////////////////////////////////
void DebugMsg(LPCSTR szFormat, int iArg1);
void DebugMsg(LPCSTR szFormat, int iArg1, int iArg2);
void DebugMsg(LPCSTR szFormat, LPCSTR szArg1 = 0, LPCSTR szArg2 = 0);
const char szDebugEnvVar[] = "_MSI_WEB_BOOTSTRAP_DEBUG";


#endif //__SETUP_H_58FA8147_50A0_4FDC_BD83_17C3A2525E0A_
