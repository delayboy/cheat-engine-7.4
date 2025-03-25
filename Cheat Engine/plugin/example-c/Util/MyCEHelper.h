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
#include<vector>
#include  <direct.h>  
#pragma comment(lib, "Psapi.lib ")
#pragma  comment(lib, "shell32.lib")
#include "cepluginsdk.h"
#include"StringHelper.h"
#include"FileHelper.h"
#define __setConstChar(...) const char* argTypesTemp[] = {__VA_ARGS__}
#define __luaFuncHandler(funcName, aTypes,...) \
__setConstChar aTypes;\
__int64 funcHandlerRetValue = luaFuncHandler(funcName, argTypesTemp,__VA_ARGS__)
//虚假全局变量
extern ExportedFunctions Exported;
extern char* myScript;
extern const char* hardwareHookScript;
extern char* antiRecordScript;
extern const char* fakeNtdllScript;

typedef union {
    int intValue;
    __int64 int64Value;
    char* strValue;
    PVOID userdata;
} AnyType;

typedef struct _CE_M128A {
    ULONGLONG Low;
    LONGLONG High;
} CEM128A, * PCEM128A;

typedef struct _CE_XSAVE_FORMAT {
    WORD   ControlWord; //修复对齐bug
    WORD   StatusWord;
    BYTE  TagWord;
    BYTE  Reserved1;
    WORD   ErrorOpcode;
    DWORD ErrorOffset;
    WORD   ErrorSelector;
    WORD   Reserved2;
    DWORD DataOffset;
    WORD   DataSelector;
    WORD   Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    CEM128A FloatRegisters[8];

#if defined(_WIN64)

    CEM128A XmmRegisters[16];
    BYTE  Reserved4[96];

#else

    CEM128A XmmRegisters[8];
    BYTE  Reserved4[224];

#endif

} CEXSAVE_FORMAT, * PCEXSAVE_FORMAT;

/**系统预制的Context存在内存对齐Bug，需要重写结构体,手动添加referencedAddress成员，
解决内存分配以16字节为单位而无法对齐的问题**/
typedef struct {

    //
    // Register parameter home addresses.
    //
    // N.B. These fields are for convience - they could be used to extend the
    //      context record in the future.
    //
    //在新增的Context中加入referencedAddress才能使结构体对齐，原Context没有这个成员
 
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;

    //
    // Control flags.
    //

    DWORD ContextFlags;
    DWORD MxCsr;

    //
    // Segment Registers and processor flags.
    //

    WORD   SegCs;
    WORD   SegDs;
    WORD   SegEs;
    WORD   SegFs;
    WORD   SegGs;
    WORD   SegSs;
    DWORD EFlags;

    //
    // Debug registers
    //

    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;

    //
    // Integer registers.
    //

    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;

    //
    // Program counter.
    //

    DWORD64 Rip;

    //
    // Floating point state.
    //
  
    CEXSAVE_FORMAT FltSave;
    /*union {
        
        struct {
            CEM128A Header[2];
            CEM128A Legacy[8];
            CEM128A Xmm0;
            CEM128A Xmm1;
            CEM128A Xmm2;
            CEM128A Xmm3;
            CEM128A Xmm4;
            CEM128A Xmm5;
            CEM128A Xmm6;
            CEM128A Xmm7;
            CEM128A Xmm8;
            CEM128A Xmm9;
            CEM128A Xmm10;
            CEM128A Xmm11;
            CEM128A Xmm12;
            CEM128A Xmm13;
            CEM128A Xmm14;
            CEM128A Xmm15;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;*/

    //
    // Vector registers.
    //

    CEM128A VectorRegister[26];
    DWORD64 VectorControl;

    //
    // Special debug control registers.
    //

    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
} CECONTEXT, * PCECONTEXT;
typedef struct
{
    __int64 self;//不一定是self我瞎猜的
    __int64 cr3;
    char* instruction;
    __int64 instructionsize;
    UINT_PTR referencedAddress;
    CECONTEXT c;
    char** bytes;
    __int64 bytesize;
    bool isfloat;
    __int64 savedsize;
    char* stack;
    __int64 compareindex;
    

}TTraceDebugInfo;
typedef struct TTreeNode
{
    char unkown[0x24];
    int Count;
    TTraceDebugInfo* Data;//data+8 = TTraceDebugInfo*
    char unkown2[0x10];
    TTreeNode** Items;
    char unkown3[0x18];
    TTreeNode* parent;
    __int64 unkown4[4];
    char* ftext;
}TTreeNode;
typedef struct
{
    char unkown[0x18];
    int Count;
    char unkown2[0x2C];
    TTreeNode* nowItem;//TTreeNode lua访问后赋值，类似selectNode的作用
    char unkown3[0x14];
    int FTopLvlCount;
    TTreeNode** Item;//TTreeNode数组的指针
}TTreeNodes;//存储了所有的TTreeNode节点信息
typedef struct
{
    char unkown[0x890];
    TTreeNodes* OpenSourceUnkown;//开源CE编译后成员移动了一位;
    TTreeNodes* Items;//TTreeNodes
    //TTreeNodes* OpenSourceUnkown;//开源CE编译后成员移动了一位;
}TCustomTreeView;

enum Align
{
    None = 0,
    Top = 1,
    Bottom = 2,
    Left = 3,
    Right = 4,
    Client = 5
};
enum DebugOptional
{
    Default = 0,
    Windows = 1,
    VEHDebug = 2,
    Kerneldebug = 3,
    DBVMdebug = 4,

};
enum BptOptional
{
    BptExecute = 0,
    BptAccess = 1,
    BptWrite = 2,

};
enum BptMethod
{
    bpmInt3 = 0, // (Software breakpoint?)
    bpmDebugRegister = 1,//(Hardware breakpoint?)
    bpmException = 2,

};
enum MemrecType
{
    vtByte = 0,
    vtWord = 1,
    vtDword = 2,
    vtQword = 3,
    vtSingle = 4,
    vtDouble = 5,
    vtString = 6,
    vtUnicodeString = 7, //Only used by autoguess
    vtByteArray = 8,
    vtBinary = 9,
    vtAutoAssembler = 11,
    vtPointer = 12, //Only used by autoguess and structures
    vtCustom = 13,
    vtGrouped = 14

};
enum TContinueOption
{
    co_run = 0, co_stepinto = 1, co_stepover = 2, co_runtill = 3
};
void luaSetComment(__int64 address, const char* comment);
int luaGetCurrentDebuggerInterface();
void luaSetBrkPoint(UINT_PTR address, int size, int trigger, int method);
void luaLoadTable(const char* fileName, bool merge);
__int64 luaGetAddress(const char* symbol);
void luaOpenProcess(int pid);
PVOID luaGetSubPascalObj(PVOID userdate, const char* paramName);
__int64 luaRunSubPascalFunc(PVOID userdate, const char* funcName, const char* argTypes[], int nArg, int rNum, ...);
PVOID luaCreateForm(bool show);
PVOID luaGetSettings(const char* keyPath);
const char* luaGetSettings_Value(PVOID setting_p, const char* keyNeedFind);
PVOID luaCreateTreeView(PVOID form);
void luaLoadString(const char* script);
PVOID luaGetTraceFile();
void luaSetUserData(PVOID objPointer, const char* name);
PVOID luaGetUserData(const char* name);
void luaPrint(const char* str);
void luaPrintf(char const* const str, ...);
__int64 luaFuncHandler(const char* funcName, LPCSTR* argTypes, int nArg, int rNum, ...);
void luaPushArgs(lua_State* L, LPCSTR* argTypes, int nArg, int rNum, va_list ap);
__int64 luaReturnValue(lua_State* L, const char* type);
__int64 v_luaFuncHandler_v(const char* funcName, LPCSTR* argTypes, int nArg, int rNum, va_list ap);
__int64 luaGetTableSubMember(PVOID userdata, const char* type, int subLevel, LPCSTR returnType, ...);
void luaSetTableSubMember(PVOID userdata, const char* type, const char* memberName, int subLevel, const char* valueType, ...);
__int64 luaRunTableSubFunc(PVOID userdata, const char* type, const char* funcName, LPCSTR* argTypes, int nArg, int rNum, ...);
void luaSetSettings_Value(PVOID setting_p, const char* keyNeedFind, const char* value);
void luaTraverseStack(lua_State* L);
const char* luaLoadScriptWithReturn(const char* script);

TTreeNode* luaTreeNodeAdd(TTreeNode* nodes, const char* content);
TTreeNode* luaTreeNodesAdd(TTreeNodes* nodes, const char* content);
TTreeNodes* luaTreeViewItems(TCustomTreeView* treeView);
TTreeNode* luaTreeNodesGetItem(TTreeNodes* treeNodes, int index);


char* luaInputQuery(const char* caption, const char* tips, char* defaultStr);
__int64 luaGetPreviousOpcode(__int64 address);
void luaRecordSetActive(PVOID record, bool active);
PVOID addScriptToTable(char* title, char* script, PVOID parent_record);
__int64 luaAllocateMemory(int size, __int64 baseAddr, bool protect);
bool luaDeAlloc(__int64 addr);

PVOID luaCreateMemoryRecord();
void luaUnRegisterLuaFunctionHighlight(const char* function_name);

void luaRegisterLuaFunctionHighlight(const char* function_name);
void luaCloseForm(PVOID form);
void luaShowForm(PVOID form);