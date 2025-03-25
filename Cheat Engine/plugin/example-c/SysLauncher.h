#pragma once
#include "cepluginsdk.h"
#include <iostream>
#include<vector>
#include <Windows.h>
#define SYMBOL_LINK "\\\\.\\SHVDriver"
#define CTL_CODE_PRINT CTL_CODE(0x8000,0x801,0,0)
#define CTL_CODE_DEBUG CTL_CODE(0x8000,0x802,0,0)
#define EXCEPTION_SINGLE_STEP 0x80000004;
extern ExportedFunctions Exported;
typedef struct _MY_ANYTYPE_IOARG {
	int needWait;
	ULONG nInBufferSize;
	ULONG optioncode;
	ULONG ret_size;//大小都固定为sizeof(MY_ANYTYPE_IOARG)，除非特殊情况
	ULONG  dwDebugEventCode; //设置成 EXCEPTION_BREAKPOINT 其他异常交给系统去搞定
	HANDLE dwProcessId;
	HANDLE dwThreadId;
	int objLock;
	union {
		struct {
			HANDLE pid;
			__int64 intCCaddr;
		}active_process;
		struct {

			PVOID ExceptionAddress;
			ULONG ExceptionFlags;//设置成0
			ULONG NumberParameters;//设置为0，这样ExceptionInformation就废了
			ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];//没用
			ULONG dwFirstChance;//设置成0
		}simple_debug_event;
		struct {
			HANDLE hFile;
			HANDLE hProcess;
			HANDLE hThread;
			PVOID lpBaseOfImage;
			ULONG dwDebugInfoFileOffset;
			ULONG nDebugInfoSize;
			PVOID lpThreadLocalBase;
			PVOID lpStartAddress; //可直接设为0
			PVOID lpImageName;
			short fUnicode;//设置为1使用unicode
		}simple_create_process;
		char strBuffer[50];

	}value;
}MY_ANYTYPE_IOARG, * PMY_ANYTYPE_IOARG;

class SysLauncher
{
private:
    CONST CHAR* drvPath;
    CONST CHAR* serviceName;
    HANDLE hDevice;


public:
	ULONG exThreadId;
	ULONG64 exThreadDr6;
	ULONG RFValue;
	int runStage;
	HANDLE dwProcess;

	HANDLE currentThread;
	DWORD dwProcessId;
	int nowThreadIndex;
	std::vector<DWORD> dwThreadIds;
	__int64 intCCaddr;
	__int64 pre_debug_rip;
	void GetProcessThreads();
    SysLauncher(CONST CHAR drvPath[50], CONST CHAR serviceName[20]);
	BOOL isReady();
    // 安装驱动
    BOOL installDvr();

    // 启动服务
    BOOL startDvr();

    // 停止服务
    BOOL stopDvr();

    // 卸载驱动
    BOOL unloadDvr();
    void connectToIoDevice();
    void closeIoDevice();
    BOOL controlIoDevice(DWORD dwIoControlCode,PMY_ANYTYPE_IOARG anyTypeInput);
	void resetEnviroment();
    ~SysLauncher();

};
extern SysLauncher* launcher;

BOOL VTSetThreadContext(HANDLE hThread, CONST CONTEXT* lpContext);
BOOL VTDebugActiveProcess(DWORD dwProcessId);
BOOL VTContinueDebugEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus);
BOOL VTGetThreadContext(HANDLE hThread, LPCONTEXT lpContext);
BOOL VTWaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds);
void InitConsoleWindow(bool switch_on);
BOOL VTChangeRegOnBP(ULONG_PTR address, BOOL remove);