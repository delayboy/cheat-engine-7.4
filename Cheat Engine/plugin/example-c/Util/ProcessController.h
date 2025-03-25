#pragma once
#include <windows.h>
#include <iostream>
#include <cstring>
#include <shellapi.h>
#include <shlobj.h>
#include <assert.h>
#include <tchar.h>
#include "psapi.h " 
#include <map>
#pragma comment(lib, "Psapi.lib ")
#pragma  comment(lib, "shell32.lib")
namespace ProCntrl
{
	HMODULE GetModule(HANDLE proccess, std::string basename);
	BOOL CreateChildProcess(const LPCSTR lpszExecFile, PROCESS_INFORMATION& proinfo, DWORD TYPE);
	__int64 EnumModuleExportFunction(HANDLE proccess, HMODULE lib, const char* funcName, bool is32);
	HMODULE InnerGetModule2(HANDLE proccess, std::string basename);
	DWORD RvaToOffset(DWORD dwRva, byte* buffer);

	__int64 getOEP(byte* pDos);

	bool is32PE(byte* pDos);

	__int64 getTLSCallBackTable(byte* buffer);

	byte* readPEFile(LPCSTR filePath);
}
