// example-c.cpp : Defines the entry point for the DLL application.
//

//#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers
// Windows Header Files:

#include"Util/MyTcpHelper.h"
#include"Util/MyCeMiniUi.h"
#include"Util/ProcessController.h"
#include <tlhelp32.h>
#include"SysLauncher.h"


int selfid;
int memorybrowserpluginid = -1; //initialize it to -1 to indicate failure (used by the DisablePlugin routine)
int addresslistPluginID = -1;
int debugpluginID = -1;
int ProcesswatchpluginID = -1;
int PointerReassignmentPluginID = -1;
int MainMenuPluginID = -1;
int DisassemblerContextPluginID = -1;
int RenderLinePluginID = -1;
int AutoAssemblerPluginID = -1;
__int64 hardwareHookAddr = 0;
__int64 hookBkPointTo = 0;
bool hookBkPointActive = false;
HHOOK wHook;
ExportedFunctions Exported;
std::map<__int64, int> brkPoints;
char g_filePath[MAX_PATH];
SysLauncher* launcher = NULL;
HMODULE this_dll_module_handle = NULL;

void CE_Lua_TcpCallback(PNetworkParam param, PPakageHeader pk_header, std::vector<char> data) {
	// 向客户端发送响应

	if (pk_header->code == 1) {
		data.push_back('\0');
		const char*  ret_str = luaLoadScriptWithReturn(data.data());
		if(ret_str)TcpSendStr(param->client_socket,ret_str);
		else TcpSendStr(param->client_socket, "lua execute return NULL", -1);
	}else if (param->client_socket) {
		char response[1] = { 0 };
		if (send(param->client_socket, response, 1, 0) < 0) {
			std::cerr << "Failed to send 0." << std::endl;

		}
	}

}
int SuspendResumeProcessThreads(DWORD processId, int sw) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to create toolhelp snapshot" << std::endl;
		return 0;
	}

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(snapshot, &threadEntry)) {
		std::cerr << "Failed to retrieve first thread information" << std::endl;
		CloseHandle(snapshot);
		return 0;
	}

	do {
		if (threadEntry.th32OwnerProcessID == processId) {
			HANDLE threadHandle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.th32ThreadID);
			if (threadHandle == nullptr) {
				std::cerr << "Failed to open thread: " << threadEntry.th32ThreadID << std::endl;
				continue;
			}
			if (sw) {
				if (SuspendThread(threadHandle) == -1) {
					std::cerr << "Failed to suspend thread: " << threadEntry.th32ThreadID << std::endl;
				}
				else {
					std::cout << "Thread suspended: " << threadEntry.th32ThreadID << std::endl;
				}
			}
			else {
				if (ResumeThread(threadHandle) == -1) {
					std::cerr << "Failed to resume thread: " << threadEntry.th32ThreadID << std::endl;
				}
				else {
					std::cout << "Thread resumed: " << threadEntry.th32ThreadID << std::endl;
				}

			}

			CloseHandle(threadHandle);
		}
	} while (Thread32Next(snapshot, &threadEntry));

	CloseHandle(snapshot);
	return 1;
}
DWORD __stdcall suspend_resume_switch_peThread(LPVOID lp) {
	char* aim_dll = (char*)lp;
	DWORD pid = *Exported.OpenedProcessID;
	HANDLE hProcess = *Exported.OpenedProcessHandle;
	for (int i = 0; i < 250; i++) //loading 5s without any target dll we will return fail;
	{
		SuspendResumeProcessThreads(pid, 1);
		Sleep(10);
		HMODULE gadll = ProCntrl::GetModule(hProcess, aim_dll); //GameAssembly.dll unityplayer KERNEL32
		if (gadll) {
			//打开进程
			luaOpenProcess(pid);
			luaPrintf("target [%s] dll load success\n", aim_dll);
			break;

		}
		printf("------------(%d/%d)----------\n", i,250);
		SuspendResumeProcessThreads(pid, 0);
		Sleep(10);
	}
	free(aim_dll);
	return 1;
}
DWORD __stdcall suspendloadpeThread(LPVOID lp) {
	
	char filePath[MAX_PATH];
	strcpy(filePath, g_filePath);
	//创建挂起进程（默认挂起）
	PROCESS_INFORMATION proinfo;
	byte* peDos = ProCntrl::readPEFile(filePath);
	bool is32 = ProCntrl::is32PE(peDos);
	int debbugerType = luaGetCurrentDebuggerInterface();
	if (is32 && debbugerType == VEHDebug) {//ProCntrl::is32PE(peDos) 32位程序加载后没有KERNEL32 所以无法注入dll很尴尬
		luaPrintf("we find 32bit program use veh suspend loading so we do trick...\n");
		ProCntrl::CreateChildProcess(filePath, proinfo, CREATE_SUSPENDED);

		//挂起进程恢复
		ResumeThread(proinfo.hThread);
		HMODULE k32 = NULL;
		while (k32 == NULL)
		{

			k32 = ProCntrl::GetModule(proinfo.hProcess, "KERNEL32");
			Sleep(1000);


		}
		__int64 gproc = ProCntrl::EnumModuleExportFunction(proinfo.hProcess, k32, "GetProcAddress", true);
		__int64 loada = ProCntrl::EnumModuleExportFunction(proinfo.hProcess, k32, "LoadLibraryA", true);

		// 终止进程
		if (!TerminateProcess(proinfo.hProcess, 0)) {
			std::cerr << "Failed to terminate process. Error: " << GetLastError() << std::endl;
		}
		else {
			std::cout << "Process terminated successfully." << std::endl;
		}

		// 关闭进程句柄
		if (!CloseHandle(proinfo.hProcess)) {
			std::cerr << "Failed to close process handle. Error: " << GetLastError() << std::endl;
		}
		ProCntrl::CreateChildProcess(filePath, proinfo, CREATE_SUSPENDED);
		char s[200];
		sprintf(s, "registerSymbol('Kernel32!GetProcAddress',0x%llx)", gproc);
		luaLoadString(s);
		sprintf(s, "registerSymbol('Kernel32!LoadLibraryA',0x%llx)", loada);
		luaLoadString(s);
		luaPrintf("pe is 32 so we test run this process first GetProcAddress:0x%llx LoadLibraryA:0x%llx", gproc, loada);

	}
	else {
		is32 = false;
		ProCntrl::CreateChildProcess(filePath, proinfo, CREATE_SUSPENDED);
		Sleep(1000);
	}


	//对于VEH由于64位可以在入口处LoadDll所以VEH也可用于阻塞式启动，32位进程由于无法通过CE本体来搜索到KERNEL32的绝对地址，所以目前无法加载但理论上还是有很多办法的


	if (debbugerType == DBVMdebug || debbugerType == Kerneldebug || (launcher != NULL && launcher->isReady())) {//如果存在驱动则使用阻塞加载法
		InitConsoleWindow(true);
		Sleep(1000);
		char* aimChar = getDynamicChars(luaGetSettings_Value(luaGetSettings(NULL), "Trick suspend target dll"));
		const char* aim_dll=luaInputQuery("Warning", "Sorry, this debbugger not support suspend loading please input the aim dll for trick loading if the result is '' we will do nothing", aimChar);//使用VT调试器则不连接进程
		free(aimChar);
		luaOpenProcess(proinfo.dwProcessId);
		if (aim_dll == NULL) return 1;
		else if (strcmp(aim_dll,"")==0) {
			luaSetSettings_Value(luaGetSettings(NULL), "Trick suspend target dll", NULL);
			return 1;
		}
		luaSetSettings_Value(luaGetSettings(NULL), "Trick suspend target dll", aim_dll);
		//挂起进程恢复
		ResumeThread(proinfo.hThread);
		CreateThread(NULL, 0, suspend_resume_switch_peThread, (LPVOID)getDynamicChars(aim_dll), 0, NULL);
		
		return 1;
	}

	//加载CE调试器
	luaOpenProcess(proinfo.dwProcessId);

	//这里其实不需要附加调试器，直接下断点就可以了
	Exported.debugProcessEx(Default);

	//重新打开一下进程消除debugProcessEx符号枚举bug
	//本质上是运行了LoadDLL和DbgHelp.dll的SymInitialize函数来实现模块枚举
	luaOpenProcess(proinfo.dwProcessId);
	//VTDebugActiveProcess(proinfo.dwProcessId);

	//ProCntrl::EnumModuleExportFunction(NULL, (HMODULE)peDos, "LdrInitializeThunk", false);
	//过TLS反调试
	__int64 addrOfCallBacks = ProCntrl::getTLSCallBackTable(peDos);//TLS回调表地址
	if (addrOfCallBacks != 0)
	{
		luaPrintf("tls:%llx", addrOfCallBacks);
		//读取第一个TLS回调函数地址
		__int64 firstCallBack = 0;
		SIZE_T realLen;
		ReadProcessMemory(proinfo.hProcess, (LPVOID)addrOfCallBacks, (LPVOID)&firstCallBack, sizeof(int), &realLen);

		//在TLS回调入口下断,使用硬件断点，防反调试
		Exported.debug_setBreakpoint(firstCallBack, 0, BptExecute, bpmInt3);//size: integer. Number of bytes to break for counting from the address. Ignored if trigger is "execute" (the default).
		brkPoints[firstCallBack] = 1;
	}

	//在OEP下断 
	__int64 baseAddress = (__int64)ProCntrl::GetModule(proinfo.hProcess, getBaseName(filePath));
	if (baseAddress) {
		__int64 oep = ProCntrl::getOEP(peDos);
		luaPrintf("UserBase:%llx\nOEP:%llx", baseAddress, oep);
		oep = baseAddress + oep;

		Exported.debug_setBreakpoint(oep, 0, BptExecute, bpmInt3);
		brkPoints[oep] = 1;

		//ntdll.dll:NtQueryInformationProcess入口断点与threadstart入口点 
		//__int64 startAddress = luaGetAddress("ntdll.LdrInitializeThunk");
		HMODULE ntdll = ProCntrl::GetModule(proinfo.hProcess, "ntdll");
		__int64 startAddress = ProCntrl::EnumModuleExportFunction(proinfo.hProcess, ntdll, "LdrInitializeThunk", is32);
		luaPrintf("system start at:%llx", startAddress);
		Exported.debug_setBreakpoint(startAddress, 0, BptExecute, bpmInt3);
		brkPoints[startAddress] = 1;
		//挂起进程恢复
		ResumeThread(proinfo.hThread);
	}
	else
	{
		luaPrintf("[ERROR]UserBase:%llx\n", baseAddress);
	}
	return 1;
}
//主脚本
void __stdcall dragLauncher(char* filePath)
{
	//如果是lnk文件则先获取文件绝对路径
	luaPrintf("file path:%s", filePath);
	std::string tail = getFileTail(filePath);
	if (tail.find("lnk") != std::string::npos)
	{
		luaPrintf("file tail:%s", tail.c_str());
		std::string tmpPath = std::string(filePath);
		strcpy(filePath, getLnkFormPath(tmpPath).c_str());
		luaPrintf("real path:%s", filePath);
	}
	//如果是PE文件则执行PE
	if (getFileTail(filePath).find("exe") != std::string::npos)
	{	
		strcpy(g_filePath, filePath);
		suspendloadpeThread(NULL);
		//CreateThread(NULL, 0, suspendloadpeThread, NULL, 0, NULL);
	
	}//如果是CT脚本
	else if (getFileTail(filePath).find("CT") != std::string::npos)
	{
		luaLoadTable(filePath, true);
	}
	else if (getFileTail(filePath).find("dll") != std::string::npos) {
		Exported.InjectDLL(filePath, "");
	}


	return;
}

void __stdcall PointersReassigned(int reserved)
{
	//可以在这里重新Hook一下默认的系统函数（因为CE重载时这些系统函数地址会发生变化），比如Exported.WriteProcessMemory函数指针
	//Check the "Pointer to pointer" objects and decide if you want to redirect them to your own routine, or not
	//Usefull for implementing your own read process memory and overriding user choises 
	//(e.g when they pick read physical memory and you want to focus on only one procesS)
	//Exported.ShowMessage("Pointers got modified");
	if (launcher != NULL&&launcher->isReady()) {
		*Exported.DebugActiveProcess = VTDebugActiveProcess;
		*Exported.ContinueDebugEvent = VTContinueDebugEvent;
		*Exported.WaitForDebugEvent = VTWaitForDebugEvent;
		*Exported.GetThreadContext = VTGetThreadContext;
		*Exported.SetThreadContext = VTSetThreadContext;
		if (Exported.ChangeRegOnBP) {
			*Exported.ChangeRegOnBP = VTChangeRegOnBP;
		}
		printf("PointersReassigned");
	}
	


	return;
}

void __stdcall processWatcherEvent(ULONG processid, ULONG peprocess, BOOL Created)
{
	//Note: This is in a seperate thread. So don't use thread-unsafe (gui) functions
	char x[100];
	if (Created)
		sprintf_s(x, 100, "Processid %x (PEPROCESS: %x) has been created", processid, peprocess);
	else
		sprintf_s(x, 100, "Processid %x (PEPROCESS: %x) has been destroyed", processid, peprocess);

	MessageBoxA(0, x, "Process Watcher Plugin Example", MB_OK);
	return;
}
//在cheat-engine/Cheat Engine/debughelper.pas中被handledebuggerplugins(@debugEvent)调用
int __stdcall debugeventplugin(LPDEBUG_EVENT DebugEvent)
{

	if (DebugEvent->dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
	{
		
		//不使用THREAD_SUSPEND_RESUME，这里是挂起不了的，只是装装样子
		HANDLE hThread = (*Exported.OpenThread)(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, TRUE, DebugEvent->dwThreadId);
		if (hThread)
		{
			
			
			if ((*Exported.SuspendThread)(hThread)) {
				CONTEXT threadContext;
				memset(&threadContext, 0, sizeof(CONTEXT));
				threadContext.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
				if ((*Exported.GetThreadContext)(hThread, &threadContext)) {
					//清理无用断点
					std::vector<__int64> unUsedAddr;
					for (std::map<__int64, int>::iterator iter = brkPoints.begin(); iter != brkPoints.end(); iter++)
					{
						if (iter->second < 1)
						{
							Exported.debug_removeBreakpoint(iter->first);
							unUsedAddr.push_back(iter->first);
						}
					}
					for (int i = 0; i < unUsedAddr.size(); i++)
					{
						brkPoints.erase(unUsedAddr[i]);
					}

					//此时的真实Rip = ExceptionAddress + 汇编代码长度
					__int64 address = threadContext.Rip;// (__int64)DebugEvent->u.Exception.ExceptionRecord.ExceptionAddress;
					if (hardwareHookAddr != 0 && address == hardwareHookAddr)
					{
						if (hookBkPointActive)
						{
							threadContext.Rip = hookBkPointTo;
							(*Exported.SetThreadContext)(hThread, &threadContext);
						}
						else
						{

							luaDeAlloc(hookBkPointTo);
							hardwareHookAddr = 0;
							hookBkPointTo = 0;
						}
					}
					else if (brkPoints.count(address) == 1)
					{
						brkPoints[address] = brkPoints[address] - 1;
					}




				}
				
			};
			(*Exported.ResumeThread)(hThread); //需要立刻挂起程序，且不恢复线程运行
			CloseHandle(hThread);

		}


	}

	//ContinueDebugEvent(DebugEvent->dwProcessId, DebugEvent->dwThreadId, DBG_CONTINUE);//DBG_EXCEPTION_NOT_HANDLED
	//luaDebugg();
	return 0; //If you return 1 you will have to call ContinueDebugEvent yourself.
}
BOOL __stdcall disassemblerContextSelectCopy(UINT_PTR* selectedAddress)
{
	if (::OpenClipboard(NULL) && ::IsClipboardFormatAvailable(CF_TEXT))
	{
		// 清空剪贴板
		if (::EmptyClipboard())
		{
			char selectedAddrStr[255];
			sprintf(selectedAddrStr, "0x%llx", *selectedAddress);

			// 分配内存并写入数据
			SIZE_T size = strlen(selectedAddrStr) + 1; // 包含 '\0'
			HGLOBAL hHandle = GlobalAlloc(GMEM_MOVEABLE, size);
			if (hHandle)
			{
				char* pData = (char*)GlobalLock(hHandle);
				if (pData)
				{
					strcpy(pData, selectedAddrStr);
					GlobalUnlock(hHandle);

					// 设置剪贴板数据
					if (!SetClipboardData(CF_TEXT, hHandle))
					{
						GlobalFree(hHandle);  // 设置失败需要释放内存
					}
				}
				else
				{
					GlobalUnlock(hHandle);
					GlobalFree(hHandle);  // 锁定失败也需要释放内存
				}
			}
		}

		// 确保总是关闭剪贴板
		CloseClipboard();
	}

	return TRUE;

}
BOOL __stdcall addresslistplugin(PPLUGINTYPE0_RECORD SelectedRecord)
{
	char x[100];
	sprintf_s(x, 100, "Selected record's description=%s Address=%0.8llx", SelectedRecord->description, (UINT64)SelectedRecord->address);
	//Exported.ShowMessage(x); //show it using CE's default messagebox
	disassemblerContextSelectCopy(&SelectedRecord->address);
	return FALSE; //return TRUE if you edited anything in the record and want to apply that to the table
}

BOOL __stdcall memorybrowserplugin(UINT_PTR* disassembleraddress, UINT_PTR* selected_disassembler_address, UINT_PTR* hexviewaddress)
{
	//Exported.ShowMessage("A Plugin function got executed");
	*hexviewaddress = *disassembleraddress; //make the disassembleraddress and hexviewaddress the same
	return TRUE;
}
BOOL __stdcall resume_memorybrowserplugin(UINT_PTR* disassembleraddress, UINT_PTR* selected_disassembler_address, UINT_PTR* hexviewaddress)
{
	SuspendResumeProcessThreads(*Exported.OpenedProcessID, 0);
	return TRUE;
}
BOOL __stdcall suspend_memorybrowserplugin(UINT_PTR* disassembleraddress, UINT_PTR* selected_disassembler_address, UINT_PTR* hexviewaddress)
{
	SuspendResumeProcessThreads(*Exported.OpenedProcessID, 1);
	return TRUE;
}

BOOL __stdcall disassemblerContextSelectCopyPopup(UINT_PTR selectedAddress, char** addressofname, BOOL* show)
{
	*addressofname = "Copy Plugin";
	return TRUE;
}

BOOL __stdcall disassemblerContextSelect(UINT_PTR* selectedAddress)
{
	if (hardwareHookAddr == 0)
	{
		hardwareHookAddr = *selectedAddress;

		char s[200];

		hookBkPointTo = luaAllocateMemory(2048, hardwareHookAddr, false);
		sprintf(s, hardwareHookScript, hookBkPointTo, hardwareHookAddr, hookBkPointTo);
		PVOID record = addScriptToTable("HardwareHook", s,NULL);
		luaRecordSetActive(record, true);
		Exported.debug_setBreakpoint(hardwareHookAddr, 0, BptExecute, bpmInt3);
		hookBkPointActive = true;
		/*char* res = luaInputQuery("Redirect Suspend Address", "Please Input Addr:",s);
		luaPrintf("input:%s", res);strToHex(res);//strToHex(res)*/

	}
	else
	{
		hookBkPointActive = false;
	}

	//luaPrintf("ContextSelectContextSelect Address=%p", *selectedAddress);
	return TRUE;
}
BOOL __stdcall disassemblerContextSelectPopup(UINT_PTR selectedAddress, char** addressofname, BOOL* show)
{
	if (hardwareHookAddr == 0)
	{
		*addressofname = "Hook BreakPoint Plugin";
	}
	else
	{
		*addressofname = "Cancal BkHook Plugin";
	}
	//luaPrintf("disassemblerContextSelectPopup Address=%llx funcName=%s", selectedAddress, *addressofname);
	return TRUE;
}

void __stdcall codeRenderLinePlugin(UINT_PTR address, char** addressStringPointer, char** bytestringpointer, char** opcodestringpointer, char** specialstringpointer, ULONG* textcolor)
{
	//可以用于加载调试符号（CE本来没有这个功能），或标注关键跳；

	if (*opcodestringpointer[0] == 'j')
	{
		if (*specialstringpointer == NULL)
		{
			const char* tmp = "Jump#";
			luaSetComment(address, tmp);
		}
		*textcolor = RGB(255, 0, 0);

	}



}

void __stdcall autoAssemblerPlugin(char** line, AutoAssemblerPhase phase, int id)
{
	
	//当调用自动汇编方法时，可以在此回调函数处逐行遍历准备运行的汇编代码;
	//此回调函数中可以改写自动汇编策略，可配合调试符号使用。
}

void OnDropFiles(HDROP hDropInfo)//
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	TCHAR szPath[MAX_PATH] = { 0 };
	UINT nCount = DragQueryFile(hDropInfo, 0xFFFFFFFF, NULL, 0);

	for (UINT idx = 0; idx < nCount; ++idx)
	{
		DragQueryFile(hDropInfo, idx, szPath, MAX_PATH);
		//MessageBox(szPath);//以消息盒子形式显示路径
		//SetDlgItemText(IDC_EDIT1, szPath);//在编辑框内显示路径	

	}
	luaPrintf("drag file:%s", szPath);
	dragLauncher(szPath);
	DragFinish(hDropInfo);
}

LRESULT CALLBACK GetMsgProc(
	_In_ int    code,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
) {
	tagMSG* msg = (tagMSG*)lParam;
	switch (msg->message)
	{
	case WM_DROPFILES:
		OnDropFiles((HDROP)msg->wParam);
		break;
	case WM_DESTROY:
		UnhookWindowsHookEx(wHook);
		break;
	case WM_CLOSE:
		UnhookWindowsHookEx(wHook);
		break;
	}
	return(CallNextHookEx(wHook, code, wParam, lParam));
}
BOOL APIENTRY DllMain(HANDLE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		this_dll_module_handle = (HMODULE)hModule;

		//MessageBox(0,"This plugin dll got loaded (This message comes from the dll)","C Plugin Example",MB_OK);
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}



BOOL __stdcall CEPlugin_GetVersion(PPluginVersion pv, int sizeofpluginversion)
{
	pv->version = CESDK_VERSION;
	pv->pluginname = "C Example v1.3 (SDK version 4: 6.0+)"; //exact strings like this are pointers to the string in the dll, so workable
	return TRUE;
}


BOOL __stdcall CEPlugin_InitializePlugin(PExportedFunctions ef, int pluginid)
{

	ADDRESSLISTPLUGIN_INIT init0;
	MEMORYVIEWPLUGIN_INIT init1;
	DEBUGEVENTPLUGIN_INIT init2;
	PROCESSWATCHERPLUGIN_INIT init3;
	POINTERREASSIGNMENTPLUGIN_INIT init4;
	MAINMENUPLUGIN_INIT init5;
	_PLUGINTYPE6_INIT init6;
	_PLUGINTYPE6_INIT init6_copy;
	_PLUGINTYPE7_INIT init7;
	_PLUGINTYPE8_INIT init8;
	MEMORYVIEWPLUGIN_INIT suspendAllThreadInit;
	MEMORYVIEWPLUGIN_INIT resumeAllThreadInit;
	selfid = pluginid;
	StartTcpServer(5151, CE_Lua_TcpCallback);

	//copy the EF list to Exported
	Exported = *ef; //Exported is defined in the .h

	if (Exported.sizeofExportedFunctions != sizeof(Exported))
		return FALSE;

	//rightclick on address plugin
	init0.name = "Sample plugin: Copy Addresslist";
	init0.callbackroutine = addresslistplugin;
	
	addresslistPluginID = Exported.RegisterFunction(pluginid, ptAddressList, &init0); //adds a plugin menu item to the memory view
	if (addresslistPluginID == -1)
	{
		Exported.ShowMessage("Failure to register the addresslist plugin");
		return FALSE;
	}

	//memory browser plugin menu:
	init1.name = "Sample plugin:  and Sync Memoryview";
	init1.callbackroutine = memorybrowserplugin;
	init1.shortcut = "Ctrl+Q";
	memorybrowserpluginid = Exported.RegisterFunction(pluginid, ptMemoryView, &init1); //adds a plugin menu item to the memory view
	if (memorybrowserpluginid == -1)
	{
		Exported.ShowMessage("Failure to register the memoryview plugin");
		return FALSE;
	}
	//memory browser plugin menu:
	resumeAllThreadInit.name = "Resume All Thread";
	resumeAllThreadInit.callbackroutine = resume_memorybrowserplugin;
	resumeAllThreadInit.shortcut = NULL;
	memorybrowserpluginid = Exported.RegisterFunction(pluginid, ptMemoryView, &resumeAllThreadInit); //adds a plugin menu item to the memory view
	if (memorybrowserpluginid == -1)
	{
		Exported.ShowMessage("Failure to register the memoryview plugin");
		return FALSE;
	}

	suspendAllThreadInit.name = "Suspend All Thread";
	suspendAllThreadInit.callbackroutine = suspend_memorybrowserplugin;
	suspendAllThreadInit.shortcut = NULL;
	memorybrowserpluginid = Exported.RegisterFunction(pluginid, ptMemoryView, &suspendAllThreadInit); //adds a plugin menu item to the memory view
	if (memorybrowserpluginid == -1)
	{
		Exported.ShowMessage("Failure to register the memoryview plugin");
		return FALSE;
	}
	//On Debug event plugin	
	init2.callbackroutine = debugeventplugin;
	debugpluginID = Exported.RegisterFunction(pluginid, ptOnDebugEvent, &init2); //adds a plugin menu item to the memory view
	if (debugpluginID == -1)
	{
		Exported.ShowMessage("Failure to register the ondebugevent plugin");
		return FALSE;
	}

	//Processwatcher event (process creation/destruction)
	init3.callbackroutine = processWatcherEvent;
	ProcesswatchpluginID = Exported.RegisterFunction(pluginid, ptProcesswatcherEvent, &init3); //adds a plugin menu item to the memory view
	if (ProcesswatchpluginID == -1)
	{
		Exported.ShowMessage("Failure to register the processwatcherevent plugin");
		return FALSE;
	}

	//Pointer reassignment event
	init4.callbackroutine = PointersReassigned;
	PointerReassignmentPluginID = Exported.RegisterFunction(pluginid, ptFunctionPointerchange, &init4); //adds a plugin menu item to the memory view
	if (PointerReassignmentPluginID == -1)
	{
		Exported.ShowMessage("Failure to register the pointer reassignment plugin");
		return FALSE;
	}

	//Main menu plugin

	init5.name = "Load CE Driver";
	init5.callbackroutine = mainmenuplugin;
	init5.shortcut = "Ctrl+R";
	MainMenuPluginID = Exported.RegisterFunction(pluginid, ptMainMenu, &init5); //adds a plugin menu item to the memory view
	if (MainMenuPluginID == -1)
	{
		Exported.ShowMessage("Failure to register the main menu plugin");
		return FALSE;
	}

	init6.name = "Script plugin: Suspend BreakPoint";
	init6.callbackroutine = disassemblerContextSelect;
	init6.callbackroutineOnPopup = disassemblerContextSelectPopup;
	init6.shortcut = "Ctrl+T";
	DisassemblerContextPluginID = Exported.RegisterFunction(pluginid, ptDisassemblerContext, &init6); //adds a plugin menu item to the memory view
	if (DisassemblerContextPluginID == -1)
	{
		Exported.ShowMessage("Failure to register the Context plugin");
		return FALSE;
	}
	init6_copy.name = "Script plugin: Copy";
	init6_copy.callbackroutine = disassemblerContextSelectCopy;
	init6_copy.callbackroutineOnPopup = disassemblerContextSelectCopyPopup;
	init6_copy.shortcut = "Ctrl+X";
	DisassemblerContextPluginID = Exported.RegisterFunction(pluginid, ptDisassemblerContext, &init6_copy); //adds a plugin menu item to the memory view
	if (DisassemblerContextPluginID == -1)
	{
		Exported.ShowMessage("Failure to register the Context plugin");
		return FALSE;
	}
	init7.callbackroutine = codeRenderLinePlugin;
	RenderLinePluginID = Exported.RegisterFunction(pluginid, ptDisassemblerRenderLine, &init7); //adds a plugin menu item to the memory view
	if (RenderLinePluginID == -1)
	{
		Exported.ShowMessage("Failure to register the RenderLine plugin");
		return FALSE;
	}


	init8.callbackroutine = autoAssemblerPlugin;
	AutoAssemblerPluginID = Exported.RegisterFunction(pluginid, ptAutoAssembler, &init8); //adds a plugin menu item to the memory view
	if (AutoAssemblerPluginID == -1)
	{
		Exported.ShowMessage("Failure to register the AutoAssembler plugin");
		return FALSE;
	}

	lua_State* lua_state = ef->GetLuaState();

	lua_register(lua_state, "lua_plugin_print", lua_plugin_print);
	luaRegisterLuaFunctionHighlight("lua_plugin_print");
	//Exported.ShowMessage("The \"Example C\" plugin got enabled");
	//创建文件拖拽回调构造
	wHook = SetWindowsHookEx(WH_GETMESSAGE, GetMsgProc, NULL, GetCurrentThreadId());
	//addScriptToTable("Deobfuscation", myScript);
	//addScriptToTable("Anti-Record", antiRecordScript);
	//addScriptToTable("Regist-Process", "{$lua}\n[ENABLE]\nregisterSymbol('proc',getAddress(process))\n[DISABLE]\nunregisterSymbol('proc')\n");
	PVOID parent = luaCreateMemoryRecord();
	std::vector<std::pair<std::string, std::string>> luaScriptList = GetManyLuaScriptFromResource(this_dll_module_handle);

	for (int i =0; i< luaScriptList.size();i++)
	{
		std::pair<std::string, std::string> it = luaScriptList[i];
		addScriptToTable(getDynamicChars(it.first), getDynamicChars(it.second),parent);

	}
	char nowPath[MAX_PATH];
	get_cwd_file(nowPath, "\\DBKKernel\\shv.sys");

	if (fileExist(nowPath))
	{
		if (luaGetCurrentDebuggerInterface()==Windows) {
			launcher = new SysLauncher(nowPath, "shv");
			if (launcher != NULL)
			{
				if (launcher->installDvr())
				{
					luaPrintf("installDvr success.\n");
				}
				if (launcher->startDvr())
				{
					luaPrintf("startDvr success.\n");
					launcher->connectToIoDevice();

				}
			}
		}
		else {
			luaPrintf("[WARNNING] we find ce not active windows debbuger in register so shv driver will be disable\n");
		}
		
	}
	else {
		get_cwd_file(nowPath, "\\DBKKernel\\MyDriver.sys");
		if (fileExist(nowPath)) {
			launcher = new SysLauncher(nowPath, "MyDriver");
			if (launcher != NULL)
			{
				if (launcher->installDvr())
				{
					luaPrintf("installDvr success.\n");
				}
				if (launcher->startDvr())
				{
					luaPrintf("startDvr success.\n");
				}
			}
		}
		
	}

	luaLoadString("json = require('dkjson')");
	luaRegisterLuaFunctionHighlight("json.decode");
	luaRegisterLuaFunctionHighlight("json.encode");
	PointersReassigned(0);
	
	return TRUE;
}


BOOL __stdcall CEPlugin_DisablePlugin(void)
{
	//clean up memory you might have allocated
	//MessageBoxA(0,"disabled plugin","Example C plugin", MB_OK);
	//卸载拖拽钩子
	luaUnRegisterLuaFunctionHighlight("lua_plugin_print");
	UnhookWindowsHookEx(wHook);
	if (launcher != NULL)
	{	
		launcher->closeIoDevice();
		if (launcher->stopDvr())
		{
			luaPrintf("stopDvr success.\n");
		}
		if (launcher->unloadDvr())
		{
			luaPrintf("unloadDvr success.\n");
		}
	}
	// 相对路径
	

	return TRUE;
}

