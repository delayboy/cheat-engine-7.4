/*
debugger.c:
This unit will handle all debugging related code, from hooking, to handling interrupts

todo: this whole thing can be moved to a few simple lines in dbvm...
*/
#pragma warning( disable: 4100 4103 4189)
#include <ntifs.h>
#include <windef.h>

#include "DBKFunc.h"
#include "interruptHook.h"
#include "MyUtil.h"
#include "debugger.h"
#include "vmxhelper.h"
#include "memscan.h"
#include "threads.h"
#ifdef AMD64 
extern void interrupt1_asmentry( void ); //declared in debuggera.asm
#else
void interrupt1_asmentry( void );
#endif

My_CriticalSection debugRoutineCS = { .name = "debugRoutineCS", .debuglevel = 1 };
My_CriticalSection vt_debug = { .name = "VT_DEBUG", .debuglevel = 1 };
My_CriticalSection guset_use_event = { .name = "GUSET_USE_EVENT", .debuglevel = 1 };
volatile struct
{
	BOOL		isDebugging;		//TRUE if a process is currently being debugged
	BOOL		stoppingTheDebugger;
	DWORD		debuggedProcessID;	//The processID that is currently debugger
	struct {
		BOOL		active;
		UINT_PTR	address;		//Up to 4 addresses to break on
		BreakType	breakType;		//What type of breakpoint for each seperate address
		BreakLength breakLength;	//How many bytes does this breakpoint look at
	} breakpoint[4];

	//...
	BOOL globalDebug;			//If set all threads of every process will raise an interrupt on taskswitch

	//while debugging:
	UINT_PTR *LastStackPointer;
	UINT_PTR *LastRealDebugRegisters;


	BOOL handledlastevent;
	
	//BOOL storeLBR;
	//int storeLBR_max;
	//UINT_PTR *LastLBRStack;

	volatile struct {		
		UINT_PTR DR0;
		UINT_PTR DR1;
		UINT_PTR DR2;
		UINT_PTR DR3;
		UINT_PTR DR6;
		UINT_PTR DR7;
		UINT_PTR reserved;
		volatile int inEpilogue; //if set the global debug bit does no faking
	} FakedDebugRegisterState[256];

	char b[1];

	//volatile BYTE DECLSPEC_ALIGN(16) fxstate[512];

	BOOL isSteppingTillClear; //when set the user has entered single stepping mode. This is a one thread only thing, so when it's active and another single step happens, discard it

} DebuggerState;



KEVENT debugger_event_WaitForContinue; //event for kernelmode. Waits till it's set by usermode (usermode function: DBK_Continue_Debug_Event sets it)
KEVENT debugger_event_CanBreak; //event for kernelmode. Waits till a break has been handled so a new one can enter
KEVENT debugger_event_WaitForDebugEvent; //event for usermode. Waits till it's set by a debugged event
KSPIN_LOCK lock;
DebugReg7 debugger_dr7_getValue(void);
void debugger_dr7_setValue(DebugReg7 value);
DebugReg6 debugger_dr6_getValue(void);
ULONG_PTR intJmpJmprip;
JUMPBACK Int1JumpBackLocation;




typedef struct _SavedStack
{
	BOOL inuse;
	QWORD stacksnapshot[600];
} SavedStack, *PSavedStack;

criticalSection StacksCS;
int StackCount;
PSavedStack *Stacks;
VT_DEBUG_EVENT_LIST debug_event_list = { 0 };
VT_DEBUG_EVENT now_g_event = { 0 };
int VtDebugEventElementHasElement() {
	return debug_event_list.size > 0;
}
int isValidVtDebugEvent(PVT_DEBUG_EVENT debug_event) {
	int valid = 1;
	if (debug_event->GuestRip == 0)valid = 0;
	if (debug_event->isHandled)valid = 0;
	UINT_PTR originaldr6 = debug_event->fakeDr[6];
	if (originaldr6 == 0x0 || originaldr6 == 0x0ff0) valid = 0;//dr6寄存器没值也是个无效事件

	return valid;
}
void innerAppendVtDebugEvent(PVT_DEBUG_EVENT debug_event, PVT_DEBUG_EVENT_LIST event_list) {
	event_list->current_pointer = (event_list->current_pointer + 1) % VT_DEBUG_EVENT_LIST_MAX_LEN;
	PVT_DEBUG_EVENT d_event = &event_list->vt_debug_events[event_list->current_pointer];
	for (int i = 0; i < 8; i++) {
		d_event->fakeDr[i] = debug_event->fakeDr[i];
	}
	
	d_event->GuestRip = debug_event->GuestRip;
	d_event->isHandled = debug_event->isHandled;
	d_event->dwThreadId = debug_event->dwThreadId;
	d_event->causeByDbvm = debug_event->causeByDbvm;
	event_list->size += 1;
	if (event_list->size > VT_DEBUG_EVENT_LIST_MAX_LEN) {
		event_list->size = VT_DEBUG_EVENT_LIST_MAX_LEN;
	}
}
void appendVtDebugEventElement(PVT_DEBUG_EVENT debug_event) {
	int cpu_id = getAPICID();
	inner_csEnter(&vt_debug, cpu_id);
	innerAppendVtDebugEvent(debug_event, &debug_event_list);
	inner_csLeave(&vt_debug, cpu_id);

}
void printDebugEvent(VT_DEBUG_EVENT_LIST debug_list) {

	if (debug_list.size < 1) {
		return;
	}
	char result[512] = { 0 };
	char temp[50] = { 0 };
	sprintf(temp, "event number:%lld\n", debug_list.size);
	sendstring(temp);
	if (1) {
		strcat(result, temp);
		int start = ((debug_event_list.current_pointer + 1 + VT_DEBUG_EVENT_LIST_MAX_LEN) - (int)debug_event_list.size) % VT_DEBUG_EVENT_LIST_MAX_LEN;
		for (int i = 0; i < debug_event_list.size && i < 6; i++) {
			int index = (start + i) % VT_DEBUG_EVENT_LIST_MAX_LEN;

			ULONG64 rip = debug_event_list.vt_debug_events[index].GuestRip;
			ULONG64 fd6 = debug_event_list.vt_debug_events[index].fakeDr[6];
			int handled = debug_event_list.vt_debug_events[index].isHandled;
			sprintf(temp, "%d > %d >  h:%d 0x%llx dr6=0x%llx\n", i, index, handled, rip, fd6);
			strcat(result, temp);
		}
		sendstring(result);
	}

}
void handleVtDebugEventFirstElement(int isHandled) {
	int cpu_id = getAPICID();
	inner_csEnter(&vt_debug, cpu_id);
	int start = ((debug_event_list.current_pointer + 1 + VT_DEBUG_EVENT_LIST_MAX_LEN) - (int)debug_event_list.size) % VT_DEBUG_EVENT_LIST_MAX_LEN;
	PVT_DEBUG_EVENT debug_event = &debug_event_list.vt_debug_events[start];
	debug_event->isHandled = isHandled;
	printDebugEvent(debug_event_list);
	inner_csLeave(&vt_debug, cpu_id);

}
void peekVtDebugEventElement(PVT_DEBUG_EVENT d_event) {
	int cpu_id = getAPICID();
	inner_csEnter(&vt_debug, cpu_id);
	int start = ((debug_event_list.current_pointer + 1 + VT_DEBUG_EVENT_LIST_MAX_LEN) - (int)debug_event_list.size) % VT_DEBUG_EVENT_LIST_MAX_LEN;
	PVT_DEBUG_EVENT debug_event = &debug_event_list.vt_debug_events[start];

	for (int i = 0; i < 8; i++) {
		d_event->fakeDr[i] = debug_event->fakeDr[i];
	}
	d_event->GuestRip = debug_event->GuestRip;
	d_event->isHandled = debug_event->isHandled;
	d_event->dwThreadId = debug_event->dwThreadId;
	d_event->causeByDbvm = debug_event->causeByDbvm;
	inner_csLeave(&vt_debug, cpu_id);
}
void popVtDebugEventElement() {
	int cpu_id = getAPICID();
	inner_csEnter(&vt_debug, cpu_id);
	int start = ((debug_event_list.current_pointer + 1 + VT_DEBUG_EVENT_LIST_MAX_LEN) - (int)debug_event_list.size) % VT_DEBUG_EVENT_LIST_MAX_LEN;
	PVT_DEBUG_EVENT debug_event = &debug_event_list.vt_debug_events[start];
	for (int i = 0; i < 8; i++) {
		debug_event->fakeDr[i] = 0;
	}
	debug_event->GuestRip = 0;
	debug_event->isHandled = 0;
	debug_event->dwThreadId = 0;
	if (debug_event_list.size >= 1)
		debug_event_list.size -= 1;

	inner_csLeave(&vt_debug, cpu_id);
}
BOOLEAN AreStringsEqual(UNICODE_STRING* moduleName, PCWSTR SourceString)
{
	UNICODE_STRING sourceUnicodeString;

	// 初始化 UNICODE_STRING 结构
	RtlInitUnicodeString(&sourceUnicodeString, SourceString);

	// 比较两个 UNICODE_STRING（不区分大小写）
	return RtlEqualUnicodeString(moduleName, &sourceUnicodeString, TRUE);
}
ULONG_PTR ForceFindJumpCode(UINT_PTR processid, ULONG_PTR begin_addr,ULONG SizeOfImage) {

	if (!begin_addr)return 0;
	ULONG_PTR offset_addr = 0;
	NTSTATUS ntStatus;
	PEPROCESS ep = NULL;
	UCHAR prechar = 0x00;
	UCHAR nowchar = 0x00;
	sendstringf("Over Module Base begin_addr:0x%llx\n", begin_addr);
	if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(processid), &ep) == STATUS_SUCCESS)
	{
		while (offset_addr < SizeOfImage) {
		
			__try
			{

				UCHAR buffer[1024] = { 0 };
				if (ReadProcessMemory((DWORD)processid, ep, (PVOID)(offset_addr+begin_addr), 1024, buffer)) {
					for (int i = 0; i < 1024; i++) {
						nowchar = buffer[i] & 0xFF;
						if (prechar == (UCHAR)0xEB && nowchar == (UCHAR)0xFE) {//0xEB 0xFE jmp 到自己
							sendstringf("Good We find at: 0x%llx\n", begin_addr + offset_addr + i - 1);
							return begin_addr + offset_addr + i - 1;
						}
						else {
							prechar = nowchar;
							
						}
							
					}
						
				}
				else {
					sendstringf("Failt To Touch at: 0x%llx\n", offset_addr + begin_addr);
					break;
				}
				
			}
			__except (1)
			{
				sendstringf("[ERROR]UnKown Error at: 0x%llx\n", offset_addr + begin_addr);
				ntStatus = STATUS_UNSUCCESSFUL;
				prechar = 0x00;
				nowchar = 0x00;
			};
			offset_addr += 1024;
		}
		ObDereferenceObject(ep);
	}
	return 0;
	


}
void EnumerateProcessModulesGetModule(UINT_PTR processid, PCWSTR aimModule,PULONG_PTR addr,PULONG size) {
	PEPROCESS ep = NULL;
	*addr = 0;
	*size = 0;
	PPEB_LDR_DATA ldr = NULL;
	if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(processid), &ep) == STATUS_SUCCESS)
	{
		KAPC_STATE oldstate;
		//DbgPrint("IOCTL_CE_GET_PEB");
		KeStackAttachProcess((PKPROCESS)ep, &oldstate);
		__try
		{
			ULONG r;
			PROCESS_BASIC_INFORMATION pbi;
			//DbgPrint("Calling ZwQueryInformationProcess");
			NTSTATUS ntStatus = ZwQueryInformationProcess(ZwCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &r);
			if (ntStatus == STATUS_SUCCESS)
			{
				//DbgPrint("pbi.UniqueProcessId=%x\n", (int)pbi.UniqueProcessId);
				//DbgPrint("pbi.PebBaseAddress=%p\n", (PVOID)pbi.PebBaseAddress);		
				P_MY_PEB peb = (P_MY_PEB)pbi.PebBaseAddress;

				ldr = peb->Ldr;
			}
			
		}
		__finally
		{
			KeUnstackDetachProcess(&oldstate);
			ObDereferenceObject(ep);
		}

		if (ldr) {
			LIST_ENTRY* listHead = &ldr->InLoadOrderModuleList;
			LIST_ENTRY* listEntry = listHead->Flink;

			while (listEntry != listHead) {
				PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);


				UNICODE_STRING* moduleName = &entry->BaseDllName;
				if (moduleName->Buffer && moduleName->Length > 0) {
					// Ensure the string is null-terminated before printing
					WCHAR safeNameBuffer[256] = { 0 };
					USHORT safeNameLength = min(moduleName->Length, sizeof(safeNameBuffer) - sizeof(WCHAR));

					RtlCopyMemory(safeNameBuffer, moduleName->Buffer, safeNameLength);

					// Print the module name
					//MyKdPrint("Module Name WCHAR: %S\n", safeNameBuffer);
					sendstringf("Module Name: %wZ\n", moduleName);
					if (AreStringsEqual(moduleName, aimModule)) {
						// Example: Printing the base address of each module
						ULONG_PTR res = (ULONG_PTR)entry->DllBase;
						ULONG resSize = (ULONG)entry->SizeOfImage;
						*addr = res;
						*size = resSize;
						sendstringf("Module Base Address1: 0x%llx\n", res);

						sendstringf("Module Base Address2: 0x%llx\n", res);
						return;
					}


				}
				else {
					sendstringf("Module Name: (unknown)\n");
				}
				listEntry = listEntry->Flink;
			}
		
		}
		else
			sendstringf("ZwQueryInformationProcess failed");
	}
	return;


}


void debugger_dr7_setGD(int state)
{

	DebugReg7 _dr7=debugger_dr7_getValue();
	_dr7.GD=state; //usually 1
	debugger_dr7_setValue(_dr7);

	
}

void debugger_dr0_setValue(UINT_PTR value)
{
	__writedr(0,value);
}

UINT_PTR debugger_dr0_getValue(void)
{
	return __readdr(0);
}

void debugger_dr1_setValue(UINT_PTR value)
{
	__writedr(1,value);
}

UINT_PTR debugger_dr1_getValue(void)
{
	return __readdr(1);
}

void debugger_dr2_setValue(UINT_PTR value)
{
	__writedr(2,value);
}

UINT_PTR debugger_dr2_getValue(void)
{
	return __readdr(2);
}

void debugger_dr3_setValue(UINT_PTR value)
{
	__writedr(3,value);
}

UINT_PTR debugger_dr3_getValue(void)
{
	return __readdr(3);
}

void debugger_dr6_setValue(UINT_PTR value)
{
	__writedr(6,value);
}

void debugger_dr7_setValue(DebugReg7 value)
{
	UINT_PTR temp=*(UINT_PTR *)&value;		
	__writedr(7,temp);
}

void debugger_dr7_setValueDword(UINT_PTR value)
{
	__writedr(7,value);	
}

UINT_PTR debugger_dr7_getValueDword(void) //I wonder why I couldn't just typecast the DebugReg7 to a dword...
{
	return __readdr(7);
}


DebugReg7 debugger_dr7_getValue(void)
{
	UINT_PTR temp=debugger_dr7_getValueDword();
	return *(DebugReg7 *)&temp;
}

UINT_PTR debugger_dr6_getValueDword(void)
{
	return __readdr(6);
}

DebugReg6 debugger_dr6_getValue(void)
{
	UINT_PTR temp=debugger_dr6_getValueDword();
	return *(DebugReg6 *)&temp;
}



void debugger_touchDebugRegister(UINT_PTR param)
{
	//DbgPrint("Touching debug register. inepilogue=\n", DebuggerState.FakedDebugRegisterState[cpunr()].inEpilogue);

	
	debugger_dr0_setValue(debugger_dr0_getValue());
	
}

void debugger_initialize(void)
{
	//DbgPrint("Initializing debugger events\n");

	KeInitializeEvent(&debugger_event_WaitForContinue, SynchronizationEvent, FALSE);	
	KeInitializeEvent(&debugger_event_CanBreak, SynchronizationEvent, TRUE); //true so the first can enter
	KeInitializeEvent(&debugger_event_WaitForDebugEvent, SynchronizationEvent, FALSE);
	KeInitializeSpinLock(&lock);
	//DbgPrint("DebuggerState.fxstate=%p\n",DebuggerState.fxstate);


	StackCount = getCpuCount() * 4;
	Stacks = (PSavedStack*)ExAllocatePool(NonPagedPool, StackCount*sizeof(PSavedStack));


	int i;
	for (i = 0; i < StackCount; i++)
	{
		Stacks[i] = (PSavedStack)ExAllocatePool(NonPagedPool, sizeof(SavedStack));
		RtlZeroMemory(Stacks[i], sizeof(SavedStack));
	}
}

void debugger_shutdown(void)
{
	if (Stacks)
	{
		int i;
		for (i = 0; i < StackCount; i++)
		{
			if (Stacks[i])
			{
				ExFreePool(Stacks[i]);
				Stacks[i] = NULL;
			}
		}

		ExFreePool(Stacks);
		Stacks = NULL;
	}
}

void debugger_growstack()
//called in passive mode
{
	if (Stacks)
	{
		KIRQL oldIRQL=KeRaiseIrqlToDpcLevel();

		csEnter(&StacksCS);
		enableInterrupts(); //csEnter disables it, but we need it

		int newStackCount = StackCount * 2;
		int i;
		PSavedStack *newStacks;
		newStacks = (PSavedStack*)ExAllocatePool(NonPagedPool, newStackCount * sizeof(PSavedStack));

		if (newStacks)
		{
			for (i = 0; i < StackCount; i++)
				newStacks[i] = Stacks[i];

			for (i = StackCount; i < newStackCount; i++)
			{
				newStacks[i] = (PSavedStack)ExAllocatePool(NonPagedPool, sizeof(SavedStack));
				if (newStacks[i])				
					RtlZeroMemory(newStacks[i], sizeof(SavedStack));				
				else
				{
					ExFreePool(newStacks);
					csLeave(&StacksCS);
					KeLowerIrql(oldIRQL);
					return;
				}
			}

			
			ExFreePool(Stacks);
			Stacks = newStacks;
		}

		csLeave(&StacksCS);
		KeLowerIrql(oldIRQL);

	}
}

void debugger_setInitialFakeState(void)
{	
	//DbgPrint("setInitialFakeState for cpu %d\n",cpunr());
	DebuggerState.FakedDebugRegisterState[cpunr()].DR0=debugger_dr0_getValue();
	DebuggerState.FakedDebugRegisterState[cpunr()].DR1=debugger_dr1_getValue();
	DebuggerState.FakedDebugRegisterState[cpunr()].DR2=debugger_dr2_getValue();
	DebuggerState.FakedDebugRegisterState[cpunr()].DR3=debugger_dr3_getValue();
	DebuggerState.FakedDebugRegisterState[cpunr()].DR6=debugger_dr6_getValueDword();
	DebuggerState.FakedDebugRegisterState[cpunr()].DR7=debugger_dr7_getValueDword();
}

VOID debugger_initHookForCurrentCPU_DPC(IN struct _KDPC *Dpc, IN PVOID  DeferredContext, IN PVOID  SystemArgument1, IN PVOID  SystemArgument2)
{
	debugger_initHookForCurrentCPU();
}

int debugger_removeHookForCurrentCPU(UINT_PTR params)
{
	//DbgPrint("Unhooking int1 for this cpu\n");
    return inthook_UnhookInterrupt(1);	
}

int debugger_initHookForCurrentCPU(void)
/*
Must be called for each cpu
*/
{
	int result=TRUE;
	//DbgPrint("Hooking int1 for cpu %d\n", cpunr());
	
	result=inthook_HookInterrupt(1,getCS() & 0xfff8, (ULONG_PTR)interrupt1_asmentry, &Int1JumpBackLocation);	

#ifdef AMD64
	if (result)
	{
		;//DbgPrint("hooked int1. Int1JumpBackLocation=%x:%llx\n", Int1JumpBackLocation.cs, Int1JumpBackLocation.eip);
	}
	else
	{
		//DbgPrint("Failed hooking interrupt 1\n");
		return result;
	}
#endif

	if (DebuggerState.globalDebug)
	{
		//set the fake state
		//debugger_setInitialFakeState();
		//DbgPrint("Setting GD bit for cpu %d\n",cpunr());

		debugger_dr7_setGD(1); //enable the GD flag		
	}

	/*if (DebuggerState.storeLBR)
	{		
		//DbgPrint("Enabling LBR logging. IA32_DEBUGCTL was %x\n", __readmsr(0x1d9));
		__writemsr(0x1d9, __readmsr(0x1d9) | 1);
		//DbgPrint("Enabling LBR logging. IA32_DEBUGCTL is  %x\n", __readmsr(0x1d9));
	}*/
		
	return result;
}

void debugger_setStoreLBR(BOOL state)
{
	return; //disabled for now
	/*
	//if (state)
	//	DbgPrint("Setting storeLBR to true\n");
	//else
	//	DbgPrint("Setting storeLBR to false\n");

	DebuggerState.storeLBR=state; //it's not THAT crucial to disable/enable it

	DebuggerState.storeLBR_max=0;

	switch (cpu_model)
    {
        case 0x2a:
        case 0x1a:
        case 0x1e:
        case 0x1f:
        case 0x2e:
        case 0x25:
        case 0x2c:
          DebuggerState.storeLBR_max=16;
          break;

        case 0x17:
        case 0x1d:
        case 0x0f:
          DebuggerState.storeLBR_max=4;
          break;

        case 0x1c:
          DebuggerState.storeLBR_max=8;
          break;
    }

	//DbgPrint("Because your cpu_model=%d I think that your storeLBR_max=%d\n", cpu_model, DebuggerState.storeLBR_max);
	*/
	
}


int debugger_setGlobalDebugState(BOOL state)
//call this BEFORE debugging, if already debugging, the user must call this for each cpu
{
	//DbgPrint("debugger_setGlobalDebugState(%d)\n",state);
	if (state)
	  DebuggerState.globalDebug=state; //on enable set this first

	if (inthook_isHooked(1))
	{
		int oldEpilogueState=DebuggerState.FakedDebugRegisterState[cpunr()].inEpilogue;

		//DbgPrint("Int 1 is hooked,%ssetting GD\n",(state ? "":"un"));
		//DbgPrint("oldEpilogueState=%d\n",oldEpilogueState);
		//debugger_setInitialFakeState();

		DebuggerState.FakedDebugRegisterState[cpunr()].inEpilogue=TRUE;
		DebuggerState.globalDebug=state;
		debugger_dr7_setGD(state);
		
		DebuggerState.FakedDebugRegisterState[cpunr()].inEpilogue=oldEpilogueState;
		

		DebuggerState.FakedDebugRegisterState[cpunr()].DR7=0x400;
		debugger_dr7_setValueDword(0x400);		

	}

	return TRUE;
}



int debugger_startDebugging(DWORD debuggedProcessID)
/*
Call this AFTER the interrupts are hooked
*/
{

	sendstring("debugger_startDebugging\n");
	ULONG_PTR adrr;
	ULONG size;
	EnumerateProcessModulesGetModule(debuggedProcessID, L"ntdll.dll",&adrr,&size);

	intJmpJmprip = ForceFindJumpCode(debuggedProcessID, adrr,size);
	
	//DbgPrint("debugger_startDebugging. Processid=%x\n",debuggedProcessID);
	Int1JumpBackLocation.eip=inthook_getOriginalEIP(1);
	Int1JumpBackLocation.cs=inthook_getOriginalCS(1);


#ifdef AMD64
	//DbgPrint("Int1 jump back = %x:%llx\n", Int1JumpBackLocation.cs, Int1JumpBackLocation.eip);
#endif
	
	DebuggerState.isDebugging=TRUE;
	DebuggerState.debuggedProcessID=debuggedProcessID;

	return TRUE;
}

int debugger_stopDebugging(void)
{	
	int i;

	//DbgPrint("Stopping the debugger if it is running\n");

	DebuggerState.stoppingTheDebugger=TRUE;	

	if (DebuggerState.globalDebug)
	{
		//touch the global debug for each debug processor
		//DbgPrint("Touching the debug registers\n");
        forEachCpuPassive(debugger_touchDebugRegister, 0);
	}

	

    DebuggerState.globalDebug=FALSE; //stop when possible, saves speed
	DebuggerState.isDebugging=FALSE;	

	for (i=0; i<4; i++)
		DebuggerState.breakpoint[i].active=FALSE;

	//unhook all processors

	forEachCpuPassive(debugger_removeHookForCurrentCPU, 0);


	return TRUE;
}

int debugger_unsetGDBreakpoint(int breakpointnr)
{
	int result=DebuggerState.breakpoint[breakpointnr].active;
	DebuggerState.breakpoint[breakpointnr].active=FALSE;
	return result; //returns true if it was active
}

int debugger_setGDBreakpoint(int breakpointnr, ULONG_PTR Address, BreakType bt, BreakLength bl)
/*
Will register a specific breakpoint. If global debug is used it'll set this debug register accordingly
*/
{
	//DbgPrint("debugger_setGDBreakpoint(%d, %x, %d, %d)\n", breakpointnr, Address, bt, bl);
	DebuggerState.breakpoint[breakpointnr].active=TRUE;
	DebuggerState.breakpoint[breakpointnr].address=Address;
	DebuggerState.breakpoint[breakpointnr].breakType=bt;
	DebuggerState.breakpoint[breakpointnr].breakLength=bl;
	return TRUE;
}

NTSTATUS debugger_waitForDebugEvent(ULONG timeout)
{
	NTSTATUS r;
	LARGE_INTEGER wait;

	//DbgPrint("debugger_waitForDebugEvent with timeout of %d\n",timeout);

	//-10000000LL=1 second
	//-10000LL should be 1 millisecond
	//-10000LL
	wait.QuadPart = -10000LL * 5;
	int has_error = 0;
	//这里为了追求调试速度，没有给CE反应时间，所以有概率让CE反应不过来从而崩溃，目前也没有太好的解决办法只能先这样了。
			//我也不确定一定是因为反应不过来，总之这种写法有概率造成R3程序崩溃，这是正常现象，不是反调试。
	int cpu_id = getAPICID();
	inner_csEnter(&guset_use_event, cpu_id);
	while (VtDebugEventElementHasElement()) {//异常链中存在事件
		VT_DEBUG_EVENT top_event = { 0 };
		peekVtDebugEventElement(&top_event);
		if (isValidVtDebugEvent(&top_event)) {//判断事件是否有效
			for (int i = 0; i < 8; i++) {
				now_g_event.fakeDr[i] = top_event.fakeDr[i];
			}
			now_g_event.GuestRip = top_event.GuestRip;
			now_g_event.dwThreadId = top_event.dwThreadId;
			now_g_event.causeByDbvm = top_event.causeByDbvm;
			now_g_event.isHandled = top_event.isHandled;
			has_error = 1;
			break;//R0驱动同一时间只能处理一个异常，因此发送一个后就退出
		}
		else {
			//经过实测这里不需要重新定向GuestRip，CE调试器自己会重定向
			//__vmx_vmwrite(GUEST_RIP, pre_debug_event.GuestRip);
			popVtDebugEventElement();//对于无效的异常事件，进行摘链处理
		}
	}
	inner_csLeave(&guset_use_event, cpu_id);
	//if (has_error) return;
	//else sendstring("[Very Big Fault] have no error but stuck in ntdll int3");			
	if (has_error) {
		if (0) {
			//DBKSuspendThread(now_g_event.dwThreadId);
			CONTEXT context;
			RtlZeroMemory(&context, sizeof(CONTEXT));
			context.ContextFlags = CONTEXT_FULL | CONTEXT_ALL; // 根据所需的上下文信息设置合适的标志
			PETHREAD spThread;
			PEPROCESS ep = NULL;
			KAPC_STATE oldstate;

			r = PsLookupProcessByProcessId((PVOID)(UINT_PTR)(DebuggerState.debuggedProcessID), &ep);//切换线程上下文
			ObDereferenceObject(ep);
			if (r != STATUS_SUCCESS)
			{
				sendstringf("[ERROR]  PsLookupProcessByProcessId:0x%llx\n", r);
				return r;
			}
			KeStackAttachProcess((PKPROCESS)ep, &oldstate);
			r = PsLookupThreadByThreadId((HANDLE)(UINT_PTR)now_g_event.dwThreadId, &spThread);
			ObDereferenceObject(spThread);
			KeUnstackDetachProcess(&oldstate);

			if (r != STATUS_SUCCESS) {
				sendstringf("[ERROR]  PsLookupThreadByThreadId:0x%llx\n", r);
				return r;
			}
		}
		
	
		sendstringf("[THREAD ID 0x%x]debugger_waitForDebugEvent:0x%llx\n", now_g_event.dwThreadId, 0x1);
		return STATUS_SUCCESS;
	}
	else {
		if (timeout == 0xffffffff) //infinite wait
			r = KeWaitForSingleObject(&debugger_event_WaitForDebugEvent, UserRequest, KernelMode, TRUE, NULL);
		else
			r = KeWaitForSingleObject(&debugger_event_WaitForDebugEvent, UserRequest, KernelMode, TRUE, &wait);
		return STATUS_UNSUCCESSFUL;

	}


		
}

NTSTATUS debugger_continueDebugEvent(BOOL handled)
/*
Only call this by one thread only, and only when there's actually a debug eevnt in progress
*/
{
	//DbgPrint("debugger_continueDebugEvent\n");
	//KeSetEvent(&debugger_event_WaitForContinue, 0,FALSE);
	handleVtDebugEventFirstElement(1);
	DebuggerState.handledlastevent=handled;
	if (!handled)sendstringf("[ERROR] debugger_continueDebugEvent UNHANDLE");
	//DBKResumeThread(now_g_event.dwThreadId);
	RtlZeroMemory(&now_g_event, sizeof(VT_DEBUG_EVENT));
	

	return STATUS_SUCCESS;
}

UINT_PTR *debugger_getLastStackPointer(void)
{
	
	return DebuggerState.LastStackPointer;
}


NTSTATUS debugger_getDebuggerState(PDebugStackState state)
{
	
	sendstringf("debugger_getDebuggerState\n");
	if (state->rip != 0 && state->threadid != 0 && state->threadid != now_g_event.dwThreadId) {
		sendstringf("[ERROR]get thread id is wrong\n");
		return STATUS_UNSUCCESSFUL;
	}
	state->threadid = (UINT64)now_g_event.dwThreadId;
	state->causedbydbvm = (UINT64)now_g_event.causeByDbvm;
	UINT_PTR originaldr6 = now_g_event.fakeDr[6];
	DebugReg6 _dr6 = *(DebugReg6*)&originaldr6;
	if (state->rip == intJmpJmprip) {
		state->rip = now_g_event.GuestRip;
		sendstringf("[INFO][THREAD][%x] call from getcontext Dr6=0x%llx 0x%llx --> 0x%llx\n", state->threadid, now_g_event.fakeDr[6], state->rip, now_g_event.GuestRip);
	}
	
	else if (state->rip == 0) {
		sendstringf("[WARN][THREAD][%x] Dr6=0x%llx guess call from wait for debug event 0x%llx --> 0x%llx\n", state->threadid, now_g_event.fakeDr[6], state->rip, now_g_event.GuestRip);
		state->rip = now_g_event.GuestRip;//这个不是来自GetContext调用要返回DebugEvent信息
	}
	else if (_dr6.BS) {
		sendstringf("[WARN][THREAD][%x] Dr6=0x%llx is one step debug so change rip whatever 0x%llx --> 0x%llx\n", state->threadid, now_g_event.fakeDr[6], state->rip, now_g_event.GuestRip);
		state->rip = now_g_event.GuestRip;//这个是单步异常所以无论如何都按error rip 来调试
	}
	else if (state->rip != now_g_event.GuestRip)sendstringf("[ERROR][THREAD][%x]  Dr6=0x%llx fail to build fake rip 0x%llx --> 0x%llx\n",  state->threadid, now_g_event.fakeDr[6], state->rip, now_g_event.GuestRip);

	state->dr6 = now_g_event.fakeDr[6]; //用自己模拟的DR6替换原始值
	state->dr7 = now_g_event.fakeDr[7]; //用自己模拟的DR6替换原始值
	state->dr0 = now_g_event.fakeDr[0]; //用自己模拟的DR6替换原始值
	state->dr1 = now_g_event.fakeDr[1]; //用自己模拟的DR6
	state->dr2 = now_g_event.fakeDr[2]; //用自己模拟的DR6替换原始值
	state->dr3 = now_g_event.fakeDr[3]; //用自己模拟的DR6替换原始值
	
	state->LBR_Count = 0;

	return STATUS_SUCCESS;

}

NTSTATUS debugger_setDebuggerState(PDebugStackState state)
{
	sendstringf("debugger_setDebuggerState\n");
	if (state->threadid != now_g_event.dwThreadId) {
		sendstringf("[ERROR]set thread id is wrong\n");
		return STATUS_UNSUCCESSFUL;
	}
	// 假设threadHandle已经从某种方式获得
	ULONG rflagMask = (1 << 16);
	if (state->rip != now_g_event.GuestRip && state->rip != intJmpJmprip) {
		sendstringf("[ERROR] CE do not find best rip to orgin 0x%llx => 0x%llx\n", state->rip, now_g_event.GuestRip);
	}
	else if (state->rip == 0) {
		sendstringf("[WARN][THREAD][%x] guess call from continue debug event 0x%llx --> 0x%llx\n", state->threadid, state->rip, now_g_event.GuestRip);
		state->rip = now_g_event.GuestRip;//这个不是来自SetContext调用要返回DebugEvent信息
	}
	else {
		sendstringf("[INFO] ef:0x%llx context_rip:0x%llx => error_ip 0x%llx Dr6=0x%llx\n",state->rflags, state->rip, now_g_event.GuestRip, state->dr6);
	}


	if (now_g_event.fakeDr[6] == 0 || now_g_event.fakeDr[6] == 0x0ff0) {//如果是取消DR6的命令，则需要模拟一个RF标志位

		state->rflags |= rflagMask;//模拟一个RF交给VT防止反复阻塞在同一个指令处

		now_g_event.fakeDr[7] = state->dr7; //记住来自CE对于Dr6的修改
		now_g_event.fakeDr[0] = state->dr0; //记住来自CE对于Dr6的修改
		now_g_event.fakeDr[1] = state->dr1;//记住来自CE对于Dr6的修改
		now_g_event.fakeDr[2] = state->dr2; //记住来自CE对于Dr6的修改
		now_g_event.fakeDr[3] = state->dr3;//记住来自CE对于Dr6的修改

	}
	ULONG rflagValue = state->rflags & rflagMask;
	if (rflagValue) {//模拟CE设置RF时，对于DR6产生的间接影响(造成DR6清零)
		now_g_event.fakeDr[6] = 0;//假装清零
	}

	
	return STATUS_SUCCESS;
	

}

int breakpointHandler_kernel(UINT_PTR* stackpointer, UINT_PTR* currentdebugregs, UINT_PTR* LBR_Stack, int causedbyDBVM)
//Notice: This routine is called when interrupts are enabled and the GD bit has been set if globaL DEBUGGING HAS BEEN USED
//Interrupts are enabled and should be at passive level, so taskswitching is possible
{



	if ((stackpointer[si_cs] & 3) == 0)
	{
		//DbgPrint("Going to wait in a kernelmode routine\n");
	}

	DebuggerState.LastStackPointer = stackpointer;
	DebuggerState.LastRealDebugRegisters = currentdebugregs;
	VT_DEBUG_EVENT debug_event;
	debug_event.GuestRip = stackpointer[si_eip];
	debug_event.dwThreadId = (ULONG64)PsGetCurrentThreadId();
	debug_event.causeByDbvm = causedbyDBVM;
	debug_event.fakeDr[7] = currentdebugregs[5];//使用旧的DR6传递错误原因
	debug_event.fakeDr[6] = currentdebugregs[4];//使用旧的DR6传递错误原因
	debug_event.fakeDr[0] = currentdebugregs[0];//使用旧的DR6
	debug_event.fakeDr[1] = currentdebugregs[1];//使用旧的DR6传递错误原因
	debug_event.fakeDr[2] = currentdebugregs[2];//使用旧的DR6传递错误原因
	debug_event.fakeDr[3] = currentdebugregs[3];//使用旧的DR6传递错误原因
	debug_event.isHandled = 0;
	sendstringf("breakpointHandler_kernel add event dr6=0x%llx\n", currentdebugregs[4]);
	int cpu_id = getAPICID();
	inner_csEnter(&guset_use_event, cpu_id);
	appendVtDebugEventElement(&debug_event);//在异常链表中注册当前异常事件
	inner_csLeave(&guset_use_event, cpu_id);
	if (intJmpJmprip)
		stackpointer[si_eip] = intJmpJmprip;
	else return 0;//找不到合适的jmp code直接交给Windows处理
	return 1;


}


int interrupt1_handler(UINT_PTR *stackpointer, UINT_PTR *currentdebugregs)
{

	HANDLE CurrentProcessID=PsGetCurrentProcessId();	

	UINT_PTR originaldr6=currentdebugregs[4];
	DebugReg6 _dr6=*(DebugReg6 *)&currentdebugregs[4];

	UINT_PTR LBR_Stack[16]; //max 16


	int causedbyDBVM = vmxusable && vmx_causedCurrentDebugBreak();



	if (DebuggerState.globalDebug)
	{
		sendstring("[ERROR] we are in global\n");
		//DbgPrint("DebuggerState.globalDebug=TRUE\n");
		//global debugging is being used
		if (_dr6.BD)
		{
			_dr6.BD = 0;
			debugger_dr6_setValue(*(UINT_PTR *)&_dr6);

		    //The debug registers are being accessed, emulate it with DebuggerState.FakedDebugRegisterState[cpunr()].DRx

			if ((stackpointer[si_cs] & 3)==0)
			{
				int instructionPointer;
	#ifdef AMD64
				int prefixpointer;
	#endif
				int currentcpunr = cpunr();
				int debugregister;
				int generalpurposeregister;
				unsigned char *instruction = (unsigned char *)stackpointer[si_eip];

				//unset this flag in DR6
				_dr6.BD = 0;
				debugger_dr6_setValue(*(UINT_PTR *)&_dr6);

				if (DebuggerState.FakedDebugRegisterState[cpunr()].inEpilogue)
				{
					((EFLAGS *)&stackpointer[si_eflags])->RF = 1; //repeat this instruction and don't break
					return 2;
				}


				//DbgPrint("handler: Setting fake dr6 to %x\n",*(UINT_PTR *)&_dr6);

				DebuggerState.FakedDebugRegisterState[cpunr()].DR6 = *(UINT_PTR *)&_dr6;

				for (instructionPointer = 0; instruction[instructionPointer] != 0x0f; instructionPointer++); //find the start of the instruction, skipping prefixes etc...

				//we now have the start of the instruction.
				//Find out which instruction it is, and which register is used
				debugregister = (instruction[instructionPointer + 2] >> 3) & 7;
				generalpurposeregister = instruction[instructionPointer + 2] & 7;

	#ifdef AMD64
				for (prefixpointer = 0; prefixpointer < instructionPointer; prefixpointer++)
				{
					//check for a REX.B prefix  (0x40  + 0x1 : 0x41)
					if ((instruction[prefixpointer] & 0x41) == 0x41)
					{
						//rex.b prefix is used, r8 to r15 are being accessed
						generalpurposeregister += 8;
					}
				}

	#endif

				//DbgPrint("debugregister=%d, generalpurposeregister=%d\n",debugregister,generalpurposeregister); 

				if (instruction[instructionPointer + 1] == 0x21)
				{
					UINT_PTR drvalue = 0;
					//DbgPrint("read opperation\n");
					//21=read
					switch (debugregister)
					{
					case 0:

						drvalue = DebuggerState.FakedDebugRegisterState[cpunr()].DR0;
						//DbgPrint("Reading DR0 (returning %x real %x)\n", drvalue, currentdebugregs[0]); 
						break;

					case 1:
						drvalue = DebuggerState.FakedDebugRegisterState[cpunr()].DR1;
						break;

					case 2:
						drvalue = DebuggerState.FakedDebugRegisterState[cpunr()].DR2;
						break;

					case 3:
						drvalue = DebuggerState.FakedDebugRegisterState[cpunr()].DR3;
						break;

					case 4:
					case 6:
						drvalue = DebuggerState.FakedDebugRegisterState[cpunr()].DR6;
						//DbgPrint("reading dr6 value:%x\n",drvalue);
						break;

					case 5:
					case 7:
						drvalue = DebuggerState.FakedDebugRegisterState[cpunr()].DR7;
						break;

					default:
						//DbgPrint("Invalid debugregister\n");
						drvalue = 0;
						break;
					}

					switch (generalpurposeregister)
					{
					case 0:
						stackpointer[si_eax] = drvalue;
						break;

					case 1:
						stackpointer[si_ecx] = drvalue;
						break;

					case 2:
						stackpointer[si_edx] = drvalue;
						break;

					case 3:
						stackpointer[si_ebx] = drvalue;
						break;

					case 4:
						if ((stackpointer[si_cs] & 3) == 3)  //usermode dr access ?
							stackpointer[si_esp] = drvalue;
						else
							stackpointer[si_stack_esp] = drvalue;

						break;

					case 5:
						stackpointer[si_ebp] = drvalue;
						break;

					case 6:
						stackpointer[si_esi] = drvalue;
						break;

					case 7:
						stackpointer[si_edi] = drvalue;
						break;

	#ifdef AMD64
					case 8:
						stackpointer[si_r8] = drvalue;
						break;

					case 9:
						stackpointer[si_r9] = drvalue;
						break;

					case 10:
						stackpointer[si_r10] = drvalue;
						break;

					case 11:
						stackpointer[si_r11] = drvalue;
						break;

					case 12:
						stackpointer[si_r12] = drvalue;
						break;

					case 13:
						stackpointer[si_r13] = drvalue;
						break;

					case 14:
						stackpointer[si_r14] = drvalue;
						break;

					case 15:
						stackpointer[si_r15] = drvalue;
						break;


	#endif
					}

				}
				else
					if (instruction[instructionPointer + 1] == 0x23)
					{
						//23=write
						UINT_PTR gpvalue = 0;
						//DbgPrint("Write operation\n");
						switch (generalpurposeregister)
						{
						case 0:
							gpvalue = stackpointer[si_eax];
							break;

						case 1:
							gpvalue = stackpointer[si_ecx];
							break;

						case 2:
							gpvalue = stackpointer[si_edx];
							break;

						case 3:
							gpvalue = stackpointer[si_ebx];
							break;

						case 4:
							if ((stackpointer[si_cs] & 3) == 3)
								gpvalue = stackpointer[si_esp];

							break;

						case 5:
							gpvalue = stackpointer[si_ebp];
							break;

						case 6:
							gpvalue = stackpointer[si_esi];
							break;

						case 7:
							gpvalue = stackpointer[si_edi];
							break;
	#ifdef AMD64
						case 8:
							gpvalue = stackpointer[si_r8];
							break;

						case 9:
							gpvalue = stackpointer[si_r9];
							break;

						case 10:
							gpvalue = stackpointer[si_r10];
							break;

						case 11:
							gpvalue = stackpointer[si_r11];
							break;

						case 12:
							gpvalue = stackpointer[si_r12];
							break;

						case 13:
							gpvalue = stackpointer[si_r13];
							break;

						case 14:
							gpvalue = stackpointer[si_r14];
							break;

						case 15:
							gpvalue = stackpointer[si_r15];
							break;

						default:
							//DbgPrint("Invalid register value\n");
							break;
	#endif
						}

						//gpvalue now contains the value to set the debug register
						switch (debugregister)
						{
						case 0:
							//DbgPrint("Writing DR0. Original value=%x new value=%x\n", currentdebugregs[0], gpvalue);
							debugger_dr0_setValue(gpvalue);
							DebuggerState.FakedDebugRegisterState[cpunr()].DR0 = debugger_dr0_getValue();
							break;

						case 1:
							debugger_dr1_setValue(gpvalue);
							DebuggerState.FakedDebugRegisterState[cpunr()].DR1 = debugger_dr1_getValue();
							break;

						case 2:
							debugger_dr2_setValue(gpvalue);
							DebuggerState.FakedDebugRegisterState[cpunr()].DR2 = debugger_dr2_getValue();
							break;

						case 3:
							debugger_dr3_setValue(gpvalue);
							DebuggerState.FakedDebugRegisterState[cpunr()].DR3 = debugger_dr3_getValue();
							break;

						case 4:
						case 6:
							//DbgPrint("Setting dr6 to %x (was %x)\n", gpvalue, DebuggerState.FakedDebugRegisterState[cpunr()].DR6);							
							_dr6 = *(DebugReg6 *)&gpvalue;

							//if (_dr6.BD) DbgPrint("Some code wants to set the BD flag to 1\n");
							



							debugger_dr6_setValue(gpvalue);
							DebuggerState.FakedDebugRegisterState[cpunr()].DR6 = debugger_dr6_getValueDword();

							if (_dr6.BD)
							{
								_dr6.BD = 0;
								debugger_dr6_setValue(gpvalue);
							}

							break;

						case 5:
						case 7:
							//make sure it doesn't set the GD flag here
							//DbgPrint("DR7 write\n");

							//if (generalpurposeregister == 15)
							//{
							//	while (1); //patchguard
							//}

							//if (DebuggerState.FakedDebugRegisterState[cpunr()].inEpilogue)
							//{
								//	DbgPrint("Was in epilogue\n");
							//}

							//check for invalid bits and raise a GPF if invalid


							gpvalue = (gpvalue | 0x400) & (~(1 << 13)); //unset the GD value

							//gpvalue=0xf0401;
							debugger_dr7_setValueDword(gpvalue);

							DebuggerState.FakedDebugRegisterState[cpunr()].DR7 = debugger_dr7_getValueDword();

							break;
						}



					}
					else
					{
						//DbgPrint("Some unknown instruction accessed the debug registers?\n");
						//if (CurrentProcessID==(HANDLE)(UINT_PTR)DebuggerState.debuggedProcessID)
						//	DbgPrint("Happened inside the target process\n");

						//DbgPrint("interrupt1_handler dr6=%x (original=%x) dr7=%d\n",_dr6, originaldr6, _dr7);
						//DbgPrint("eip=%x\n",stackpointer[si_eip]);
					}

				//adjust eip to after this instruction
				stackpointer[si_eip] += instructionPointer + 3; //0f xx /r

				return 1; //don't tell windows about it
			}
			else
			{
				//DbgPrint("DR6.BD == 1 in USERMODE! WTF\n");
				_dr6.BD = 0;
				debugger_dr6_setValue(*(UINT_PTR *)&_dr6);
				DebuggerState.FakedDebugRegisterState[cpunr()].DR6 = debugger_dr6_getValueDword();
			}
		}
	}

	if (CurrentProcessID == (HANDLE)(UINT_PTR)DebuggerState.debuggedProcessID)//加入白名单防止调试陷阱
	{
		//DbgPrint("DebuggerState.isDebugging\n");
		//check if this should break
		ULONG_PTR isReadOrWrite = 0; //判断断点是否为执行断点
		ULONG_PTR ref_dr = 0;//当区使用的DR寄存器的值
		DebugReg6 myDr6 = debugger_dr6_getValue();
		DebugReg7 myDr7 = debugger_dr7_getValue();
		BOOL my_should_break = 0;//加入白名单防止调试陷阱
		int showWitchDr = 0;
		if (myDr6.B0) {
			isReadOrWrite = myDr7.RW0;
			showWitchDr = 0;
			ref_dr = debugger_dr0_getValue();
		}
		else if (myDr6.B1) {
			isReadOrWrite = myDr7.RW1;
			showWitchDr = 1;
			ref_dr = debugger_dr1_getValue();
		}
		else if (myDr6.B2) {
			isReadOrWrite = myDr7.RW2;
			showWitchDr = 2;
			ref_dr = debugger_dr2_getValue();

		}
		else if (myDr6.B3) {
			isReadOrWrite = myDr7.RW3;
			showWitchDr = 3;
			ref_dr = debugger_dr3_getValue();

		}
		if (myDr6.BS) { //如果是单步异常则不忽略
			my_should_break = 1;
			if (stackpointer[si_eip] == intJmpJmprip) {//单步异常的intJmp需要忽略
				my_should_break = 0;
			}
		}
		else if (isReadOrWrite) {

			for (int i = 0; i < 4; i++) {
				ULONG_PTR aim_addr = DebuggerState.breakpoint[i].address;
				if (aim_addr - 16 < ref_dr && ref_dr < aim_addr + 16) {
					my_should_break = 1;
					break;
				}
			}

		}
		else {
			for (int i = 0; i < 4; i++) {
				if (DebuggerState.breakpoint[i].address == stackpointer[si_eip]) {
					my_should_break = 1;
					break;
				}
			}
		}
		
		
		sendstringf("ThreadId= 0x%x bk1=0x%llx bk2=0x%llx bk3=0x%llx bk4=0x%llx rip = 0x%llx, dr%d = 0x%llx, Dr6.BS = 0x%llx, ReadOrWrite = 0x%llx, dr6 = 0x%llx, dr7 = 0x%llx, rflags = 0x%llx, my_should_break =0x%x\r\n", \
			PsGetCurrentThreadId(), DebuggerState.breakpoint[0].address, DebuggerState.breakpoint[1].address, DebuggerState.breakpoint[2].address, DebuggerState.breakpoint[3].address, stackpointer[si_eip], showWitchDr, currentdebugregs[showWitchDr], myDr6.BS, isReadOrWrite, debugger_dr6_getValue(), getDR7(), stackpointer[si_eflags], my_should_break);
		if (my_should_break == 0) return 0; //Let windows handle it
	}

	if (DebuggerState.isSteppingTillClear) //this doesn't really work because when the state comes back to interruptable the system has a critical section lock on the GUI, so yeah... I really need a DBVM display driver for this
	{
		
		if ((((PEFLAGS)&stackpointer[si_eflags])->IF == 0) || (KeGetCurrentIrql() != PASSIVE_LEVEL))
		{
			((PEFLAGS)&stackpointer[si_eflags])->TF = 1;
			((PEFLAGS)&stackpointer[si_eflags])->RF = 1;
			debugger_dr6_setValue(0xffff0ff0);
			return 1;
		}

		DebuggerState.isSteppingTillClear = FALSE;	
	}

	
	if (DebuggerState.isDebugging)
	{
		
		
		if (CurrentProcessID == (HANDLE)(UINT_PTR)DebuggerState.debuggedProcessID)
		{
			sendstring("CE Dbg Debug Begin\n");
			UINT_PTR originaldebugregs[6];
			UINT64 oldDR7 = getDR7();


			if ((((PEFLAGS)&stackpointer[si_eflags])->IF == 0) || (KeGetCurrentIrql() != PASSIVE_LEVEL))
			{
				//There's no way to display the state to the usermode part of CE
				//DbgPrint("int1 at unstoppable location");
				if (!KernelCodeStepping)
				{
					((PEFLAGS)&stackpointer[si_eflags])->TF = 0; //just give up stepping
				//	DbgPrint("Quitting this");
				}
				else
				{
					//	DbgPrint("Stepping until valid\n");
					((PEFLAGS)&stackpointer[si_eflags])->TF = 1; //keep going until a valid state
					DebuggerState.isSteppingTillClear = TRUE; //Just in case a taskswitch happens right after enabling passive level with interrupts
				}

				((PEFLAGS)&stackpointer[si_eflags])->RF = 1;
				debugger_dr6_setValue(0xffff0ff0);
				return 1;
			}

			DebuggerState.isSteppingTillClear = FALSE;



			//DbgPrint("CurrentProcessID==(HANDLE)(UINT_PTR)DebuggerState.debuggedProcessID\n");

			if (DebuggerState.globalDebug)
			{
				originaldebugregs[0] = DebuggerState.FakedDebugRegisterState[cpunr()].DR0;
				originaldebugregs[1] = DebuggerState.FakedDebugRegisterState[cpunr()].DR1;
				originaldebugregs[2] = DebuggerState.FakedDebugRegisterState[cpunr()].DR2;
				originaldebugregs[3] = DebuggerState.FakedDebugRegisterState[cpunr()].DR3;
				originaldebugregs[4] = DebuggerState.FakedDebugRegisterState[cpunr()].DR6;
				originaldebugregs[5] = DebuggerState.FakedDebugRegisterState[cpunr()].DR7;
			}

			//DbgPrint("BP in target process\n");

			//no extra checks if it's caused by the debugger or not. That is now done in the usermode part
			//if (*(PEFLAGS)(&stackpointer[si_eflags]).IF)	
/*
			if (((PEFLAGS)&stackpointer[si_eflags])->IF==0)
			{
				//DbgPrint("Breakpoint while interrupts are disabled: %x\n",stackpointer[si_eip]);
				//An breakpoint happened while IF was 0. Step through the code untill IF is 1
				((PEFLAGS)&stackpointer[si_eflags])->RF=1;
				((PEFLAGS)&stackpointer[si_eflags])->TF=1; //keep going until IF=1
				DbgPrint("IF==0\n");
				return 1; //don't handle it but also don't tell windows
			}*/

			//set the real debug registers to what it is according to the guest (so taskswitches take over these values) .... shouldn't be needed as global debug is on which fakes that read...



			if (DebuggerState.globalDebug)
			{
				//enable the GD flag for taskswitches that will occur as soon as interrupts are enabled
				//this also means: DO NOT EDIT THE DEBUG REGISTERS IN GLOBAL DEBUG MODE at this point. Only in the epilogue

				if (!DebuggerState.stoppingTheDebugger) //This is set when the driver is unloading. So do NOT set it back then
					debugger_dr7_setGD(DebuggerState.globalDebug);
			}
			else
			{
				//unset ALL debug registers before enabling taskswitching. Just re-enable it when back when interrupts are disabled again
				debugger_dr7_setValueDword(0x400);
				debugger_dr0_setValue(0);
				debugger_dr1_setValue(0);
				debugger_dr2_setValue(0);
				debugger_dr3_setValue(0);
				debugger_dr6_setValue(0xffff0ff0);//清除DR6防止持续发生断点
				((PEFLAGS)&stackpointer[si_eflags])->TF = 0; //防止持续单步

			}

			//start the windows taskswitching mode

			//if (1) return 1;

			//save the state of the thread to a place that won't get overwritten

			//todo: breaks 32-bit
			//int i;
			BOOL NeedsToGrowStackList = FALSE;
			PSavedStack SelectedStackEntry = NULL;
			/*
			csEnter(&StacksCS);
			for (i = 0; i < StackCount; i++)
			{
				if (Stacks[i]->inuse == FALSE)
				{
					SelectedStackEntry = Stacks[i];
					SelectedStackEntry->inuse = TRUE;
					RtlCopyMemory(SelectedStackEntry->stacksnapshot, stackpointer, 600 * 8);

					if (i > StackCount / 2)
						NeedsToGrowStackList = TRUE;

					break;
				}
			}
			csLeave(&StacksCS);

			enableInterrupts();

			//grow stack if needed

			if (NeedsToGrowStackList)
				debugger_growstack();
		*/

			{
				int rs=1;	

				//DbgPrint("calling breakpointHandler_kernel\n");

				if (SelectedStackEntry == NULL) //fuck
					rs = breakpointHandler_kernel(stackpointer, currentdebugregs, LBR_Stack, causedbyDBVM);
				else
					rs = breakpointHandler_kernel((UINT_PTR *)(SelectedStackEntry->stacksnapshot), currentdebugregs, LBR_Stack, causedbyDBVM);

				
				
				//DbgPrint("After handler\n");
/*
				if (SelectedStackEntry)  //restore the stack
				{
					RtlCopyMemory(stackpointer, SelectedStackEntry->stacksnapshot, 600 * 8);
					SelectedStackEntry->inuse = FALSE;
				}
				*/
				
				//DbgPrint("rs=%d\n",rs);


				disableInterrupts();

				//restore the 


				//we might be on a different CPU now
				if (DebuggerState.globalDebug)
				{
					DebuggerState.FakedDebugRegisterState[cpunr()].DR0=originaldebugregs[0];
					DebuggerState.FakedDebugRegisterState[cpunr()].DR1=originaldebugregs[1];
					DebuggerState.FakedDebugRegisterState[cpunr()].DR2=originaldebugregs[2];
					DebuggerState.FakedDebugRegisterState[cpunr()].DR3=originaldebugregs[3];
					DebuggerState.FakedDebugRegisterState[cpunr()].DR6=originaldebugregs[4];
					DebuggerState.FakedDebugRegisterState[cpunr()].DR7=originaldebugregs[5];
				}
				else
				{
					
					/*if (getDR7() != oldDR7)
					{
						DbgPrint("Something changed DR7. old=%llx new=%llx\n",oldDR7, getDR7());
					}*/

					
					//set the debugregisters to what they where set to before taskswitching was enable
					//with global debug this is done elsewhere
					debugger_dr0_setValue(currentdebugregs[0]);
					debugger_dr1_setValue(currentdebugregs[1]);
					debugger_dr2_setValue(currentdebugregs[2]);
					debugger_dr3_setValue(currentdebugregs[3]);
					debugger_dr6_setValue(currentdebugregs[4]);

					if ((currentdebugregs[5] >> 13) & 1)
					{
					//	DbgPrint("WTF? GD is 1 in currentdebugregs[5]: %llx\n", currentdebugregs[5]);
					}
					else
						debugger_dr7_setValue(*(DebugReg7 *)&currentdebugregs[5]);	
						
				}
				
				return rs;
			}
		}
		else 
		{
			//DbgPrint("Not the debugged process (%x != %x)\n",CurrentProcessID,DebuggerState.debuggedProcessID );
			//check if this break is due to a breakpoint ce has set. (during global debug threadsurfing))
			//do that by checking if the breakpoint condition exists in the FAKE dr7 registers
			//if so, let windows handle it, if not, it is caused by ce, which then means, skip (so execute normally)

			if (DebuggerState.globalDebug)
			{			
				DebugReg6 dr6=debugger_dr6_getValue();
				DebugReg7 dr7=*(DebugReg7 *)&DebuggerState.FakedDebugRegisterState[cpunr()].DR7;

				//real dr6		//fake dr7
				if ((dr6.B0) && (!(dr7.L0 || dr7.G0))) { /*DbgPrint("setting RF because of B0\n");*/ ((PEFLAGS)&stackpointer[si_eflags])->RF=1; return 1; } //break caused by DR0 and not expected by the current process, ignore this bp and continue
				if ((dr6.B1) && (!(dr7.L1 || dr7.G1))) { /*DbgPrint("setting RF because of B1\n");*/ ((PEFLAGS)&stackpointer[si_eflags])->RF=1; return 1; } //		...		DR1		...
				if ((dr6.B2) && (!(dr7.L2 || dr7.G2))) { /*DbgPrint("setting RF because of B2\n");*/ ((PEFLAGS)&stackpointer[si_eflags])->RF=1; return 1; }  //		...		DR2		...
				if ((dr6.B3) && (!(dr7.L3 || dr7.G3))) { /*DbgPrint("setting RF because of B3\n");*/ ((PEFLAGS)&stackpointer[si_eflags])->RF=1; return 1; }  //		...		DR3		...
			}

			if (causedbyDBVM)
				return 1; //correct PA, bad PID, ignore BP

			if (DebuggerState.isSteppingTillClear) //shouldn't happen often
			{
				//DbgPrint("That thing that shouldn\'t happen often happened\n");
				((PEFLAGS)&stackpointer[si_eflags])->TF = 0;

				DebuggerState.isSteppingTillClear = 0;
				return 1; //ignore
			}

			//DbgPrint("Returning unhandled. DR6=%x", debugger_dr6_getValueDword());
			
			return 0; //still here, so let windows handle it

		}
	}
	else
		return 0; //Let windows handle it

	//get the current processid
	//is it being debugged
	//if yes, check if the breakpoint is something done by me
	//if no, exit
	
}

int interrupt1_centry(UINT_PTR *stackpointer) //code segment 8 has a 32-bit stackpointer
{


	UINT_PTR before;//,after;
	UINT_PTR currentdebugregs[6]; //used for determining if the current bp is caused by the debugger or not
	int handled=0; //if 0 at return, the interupt will be passed down to the operating system
	QWORD naddress;
	//DbgPrint("interrupt1_centry cpunr=%d esp=%x\n",cpunr(), getRSP());

	//bsod crashfix, but also disables kernelmode stepping
	IDT idt;
	GetIDT(&idt);

	naddress = idt.vector[1].wLowOffset + (idt.vector[1].wHighOffset << 16);
#ifdef AMD64
	naddress += ((UINT64)idt.vector[1].TopOffset << 32);
#endif
	stackpointer[si_errorcode] = (UINT_PTR)naddress; //the errorcode is used as address to call the original function if needed
		


	/*
	if (Int1JumpBackLocation.eip != naddress) //no, just fucking no (patchguard will replace all inthandlers with invalid ones and then touch dr7)	
	{
		//todo: the usual, but make sure not to use dbgprint or anything that could trigger a software int
		if (DebuggerState.globalDebug)
		{
			debugger_dr7_setGD(DebuggerState.globalDebug);
			stackpointer[si_eip] += 4;
			return 1;
		}
	}
	*/






	before=getRSP();

	//Fetch current debug registers
	currentdebugregs[0]=debugger_dr0_getValue();
	currentdebugregs[1]=debugger_dr1_getValue();
	currentdebugregs[2]=debugger_dr2_getValue();
	currentdebugregs[3]=debugger_dr3_getValue();
	currentdebugregs[4]=debugger_dr6_getValueDword();
	currentdebugregs[5]=debugger_dr7_getValueDword();


	handled=interrupt1_handler(stackpointer, currentdebugregs);

	//epilogue:
	//At the end when returning:
	
	

	//
	//--------------------------------------------------------------------------
	//--------------EPILOGUE (AFTER HAVING HANDLED THE BREAKPOINT)--------------
	//--------------------------------------------------------------------------
	//
	
	
	disableInterrupts(); //just making sure..	


	DebuggerState.FakedDebugRegisterState[cpunr()].inEpilogue=1;
	debugger_dr7_setGD(0); //make sure the GD bit is disabled (int1 within int1, oooh the fun..., and yes, THIS itself will cause one too)
	DebuggerState.FakedDebugRegisterState[cpunr()].inEpilogue=1; //just be sure...


	//if (inthook_isDBVMHook(1))
	//{
		//update the int1 return address, could have been changed
		

		

		//DbgPrint("This was a dbvm hook. Changing if the interrupt return address is still valid\n");

	//	Int1JumpBackLocation.cs=idt.vector[1].wSelector;
	//	naddress=idt.vector[1].wLowOffset+(idt.vector[1].wHighOffset << 16);
#ifdef AMD64
	//	naddress+=((UINT64)idt.vector[1].TopOffset << 32);		
#endif
	   


	//}
	

	if (DebuggerState.globalDebug) //DR's are only accesses when there are DR's(no idea how it handles breakpoints in a different process...), so set them in each thread even those that don't belong original: && (PsGetCurrentProcessId()==(HANDLE)DebuggerState.debuggedProcessID))
	{
		//set the breakpoint in this thread. 		
        DebugReg6 dr6=debugger_dr6_getValue();
		//DebugReg7 dr7=debugger_dr7_getValue();

		DebugReg6 _dr6=*(DebugReg6 *)&DebuggerState.FakedDebugRegisterState[cpunr()].DR6;
        DebugReg7 _dr7=*(DebugReg7 *)&DebuggerState.FakedDebugRegisterState[cpunr()].DR7;
		int debugregister=0, breakpoint=0;
		


        //first clear the DR6 bits caused by the debugger

		if (!handled)
		{
			//it's going to get sent to windows
			if (dr6.BD && _dr7.GD) _dr6.BD=1; //should already have been done, but what the heck...
			if (dr6.B0 && (_dr7.L0 || _dr7.G0)) _dr6.B0=1;
			if (dr6.B1 && (_dr7.L1 || _dr7.G1)) _dr6.B1=1;
			if (dr6.B2 && (_dr7.L2 || _dr7.G2)) _dr6.B2=1;
			if (dr6.B3 && (_dr7.L3 || _dr7.G3)) _dr6.B3=1;

			_dr6.BS=dr6.BS;
			_dr6.BT=dr6.BT;
			//DbgPrint("epilogue: Setting fake dr6 to %x (fake=%x)\n",*(DWORD *)&dr6, *(DWORD *)&_dr6);
		}
		

		debugger_dr6_setValue(0xffff0ff0);

		
		//set the debug registers of active breakpoints. Doesn't have to be in the specified order. Just find an unused debug registers
		//check DebuggerState.FakedDebugRegisterState[cpunumber].DR7 for unused breakpoints

		//set state to what the guest thinks it is
		debugger_dr0_setValue(DebuggerState.FakedDebugRegisterState[cpunr()].DR0);
		debugger_dr1_setValue(DebuggerState.FakedDebugRegisterState[cpunr()].DR1);
		debugger_dr2_setValue(DebuggerState.FakedDebugRegisterState[cpunr()].DR2);
		debugger_dr3_setValue(DebuggerState.FakedDebugRegisterState[cpunr()].DR3);
		debugger_dr6_setValue(DebuggerState.FakedDebugRegisterState[cpunr()].DR6);

		
		
		for (breakpoint=0; breakpoint<4; breakpoint++)
		{
			
			if (DebuggerState.breakpoint[breakpoint].active)
			{
				
				int foundone=0;
			//	DbgPrint("Want to set breakpoint %d\n",breakpoint);
			
				

				//find a usable debugregister
				while ((debugregister<4) && (foundone==0))				
				{
				
					if (DebuggerState.FakedDebugRegisterState[cpunr()].inEpilogue==0)
					{
						DebuggerState.FakedDebugRegisterState[cpunr()].inEpilogue=1;
					}
					

					//check if this debugregister is usable
					if (((DebuggerState.FakedDebugRegisterState[cpunr()].DR7 >> (debugregister*2)) & 3)==0)  //DR7.Gx and DR7.Lx are 0
					{
					  //  DbgPrint("debugregister %d is free to be used\n",debugregister);
						foundone=1;
						
						//set address
						switch (debugregister)
						{
							case 0:	
								debugger_dr0_setValue(DebuggerState.breakpoint[breakpoint].address);
								_dr7.L0=1;
								_dr7.LEN0=DebuggerState.breakpoint[breakpoint].breakLength;
								_dr7.RW0=DebuggerState.breakpoint[breakpoint].breakType;
								break;

							case 1:
								debugger_dr1_setValue(DebuggerState.breakpoint[breakpoint].address);
								_dr7.L1=1;
								_dr7.LEN1=DebuggerState.breakpoint[breakpoint].breakLength;
								_dr7.RW1=DebuggerState.breakpoint[breakpoint].breakType;
								break;

							case 2:
								debugger_dr2_setValue(DebuggerState.breakpoint[breakpoint].address);
								_dr7.L2=1;
								_dr7.LEN2=DebuggerState.breakpoint[breakpoint].breakLength;
								_dr7.RW2=DebuggerState.breakpoint[breakpoint].breakType;
								break;

							case 3:
								debugger_dr3_setValue(DebuggerState.breakpoint[breakpoint].address);
								_dr7.L3=1;
								_dr7.LEN3=DebuggerState.breakpoint[breakpoint].breakLength;
								_dr7.RW3=DebuggerState.breakpoint[breakpoint].breakType;
								break;
						}
						

					}

					debugregister++;

				}
				
				
			}
			
			
		}
		

		debugger_dr7_setValue(_dr7);

		//DbgPrint("after:\n");

		//DbgPrint("after fake DR0=%x real DR0=%x\n",DebuggerState.FakedDebugRegisterState[currentcpunr].DR0, debugger_dr0_getValue());
		//DbgPrint("after fake DR1=%x real DR1=%x\n",DebuggerState.FakedDebugRegisterState[currentcpunr].DR1, debugger_dr1_getValue());
		//DbgPrint("after fake DR2=%x real DR2=%x\n",DebuggerState.FakedDebugRegisterState[currentcpunr].DR2, debugger_dr2_getValue());
		//DbgPrint("after fake DR3=%x real DR3=%x\n",DebuggerState.FakedDebugRegisterState[currentcpunr].DR3, debugger_dr3_getValue());
		//DbgPrint("after fake DR6=%x real DR6=%x\n",DebuggerState.FakedDebugRegisterState[currentcpunr].DR6, debugger_dr6_getValueDword());
		//DbgPrint("after fake DR7=%x real DR7=%x\n",DebuggerState.FakedDebugRegisterState[currentcpunr].DR7, debugger_dr7_getValueDword());

	}
	else
	{
		//not global debug, just clear all flags and be done with it
		if (handled)
			debugger_dr6_setValue(0xffff0ff0);
	
	}

	disableInterrupts();


	if (handled == 2)
	{
		//DbgPrint("handled==2\n");		
		handled = 1; //epilogue = 1 Dr handler
	}
	else
	{		
		//not handled by the epilogue set DR0, so the actual epilogue
		//DbgPrint("handled==1\n");
		
		if (DebuggerState.globalDebug)
		{
			DebuggerState.FakedDebugRegisterState[cpunr()].inEpilogue=0;

			if (!DebuggerState.stoppingTheDebugger)
				debugger_dr7_setGD(DebuggerState.globalDebug); //set it back to 1, if not unloading
		}
	}
	//after=getRSP();

	//DbgPrint("before=%llx after=%llx\n",before,after);

	//DbgPrint("end of interrupt1_centry. eflags=%x", stackpointer[si_eflags]);

	//if branch tracing set lbr back on (get's disabled on debug interrupts)	
	/*
	  if (DebuggerState.storeLBR)
	    __writemsr(0x1d9, __readmsr(0x1d9) | 1);
    */
		



	return handled;
}

#ifndef AMD64
_declspec( naked ) void interrupt1_asmentry( void )
//This routine is called upon an interrupt 1, even before windows gets it
{
	__asm{
		//change the start of the stack so that instructions like setthreadcontext do not affect the stack it when it's frozen and waiting for input
		//meaning the setting of debug registers will have to be done with the changestate call

		//sub esp,4096
		//push [esp+4096+0+16] //optional ss
		//push [esp+4096+4+12] //optional esp
		//push [esp+4096+8+8] //eflags
		//push [esp+4096+12+4] //cs
		//push [esp+4096+16+0] //eip

		cld //reset the direction flag
		
		
		
		



		//save stack position
		push 0 //push an errorcode on the stack so the stackindex can stay the same
		push ebp
		mov ebp,esp

		//save state
		pushad
		xor eax,eax
		mov ax,ds
		push eax

		mov ax,es
		push eax

		mov ax,fs
		push eax

		mov ax,gs
		push eax

		//save fpu state
		//save sse state
		
		mov ax,0x23 //0x10 should work too, but even windows itself is using 0x23
		mov ds,ax
		mov es,ax
		mov gs,ax
		mov ax,0x30
		mov fs,ax

		
		

		push ebp
		call interrupt1_centry

		cmp eax,1	//set flag

		//restore state
		pop gs
		pop fs
		pop es
		pop ds
		popad

		pop ebp		

		je skip_original_int1
		
		add esp,4 //undo errorcode push (add effects eflags, so set it at both locations)

		jmp far [Int1JumpBackLocation]

skip_original_int1:
		add esp,4 //undo errorcode push
		iretd
	}
}
#endif
