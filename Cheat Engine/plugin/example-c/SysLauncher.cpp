#include"SysLauncher.h"
#include"Util/MyCEHelper.h"
#include"Util/ProcessController.h"
#include <tlhelp32.h>

FILE* fpOut = NULL;
FILE* fpErr = NULL;
FILE* fpIn = NULL;

void InitConsoleWindow(bool switch_on)
{

    const HWND consoleWindow = GetConsoleWindow();
    bool no_handle = consoleWindow == NULL;
    if (switch_on && no_handle)
    {
        int hCrt;
        FILE* hf;

        AllocConsole();
        if (fpIn != NULL) fclose(fpIn);
        if (fpOut != NULL) fclose(fpOut);
        if (fpErr != NULL) fclose(fpErr);
        fpIn = freopen("conin$", "r", stdin);//重定向输入流
        fpOut = freopen("conout$", "w", stdout);
        fpErr = freopen("conout$", "w", stderr);
        // test code
        printf("InitConsoleWindow OK!\n");
    }
    else if (!switch_on && !no_handle) {
        printf("Closing Console Window...\n");
        fflush(stdout);
        fflush(stderr);
        fflush(stdin);
        // Close the file streams if they were redirected

        FreeConsole();
        if (fpIn != NULL) fclose(fpIn);
        if (fpOut != NULL) fclose(fpOut);
        if (fpErr != NULL) fclose(fpErr);

        // Redirect stdout and stderr back to NUL to avoid invalid pointer issues
        fpIn = freopen("NUL:", "r", stdin);//重定向输入流
        fpOut = freopen("NUL:", "w", stdout);
        fpErr = freopen("NUL:", "w", stderr);

    }
}
SysLauncher::SysLauncher(const CHAR drvPath[50], const CHAR serviceName[20])
{
    this->drvPath = drvPath;
    this->serviceName = serviceName;
    this->hDevice = INVALID_HANDLE_VALUE;
    this->resetEnviroment();
   
}

BOOL SysLauncher::isReady()
{
    return this->hDevice != INVALID_HANDLE_VALUE;
}

BOOL SysLauncher::installDvr()
{
    // 打开服务控制管理器数据库
    SC_HANDLE schSCManager = OpenSCManagerA(
        NULL,                   // 目标计算机的名称,NULL：连接本地计算机上的服务控制管理器
        NULL,                   // 服务控制管理器数据库的名称，NULL：打开 SERVICES_ACTIVE_DATABASE 数据库
        SC_MANAGER_ALL_ACCESS   // 所有权限
    );

    if (schSCManager == NULL) {
        return FALSE;
    }
    // 打开服务
    SC_HANDLE hs = OpenServiceA(
        schSCManager,           // 服务控件管理器数据库的句柄
        serviceName,            // 要打开的服务名
        SERVICE_ALL_ACCESS      // 服务访问权限：所有权限
    );
    if (hs != NULL)
    {
        printf("服务已存在无需加载\n");
        return TRUE;
    }
    // 创建服务对象，添加至服务控制管理器数据库
    SC_HANDLE schService = CreateServiceA(
        schSCManager,               // 服务控件管理器数据库的句柄
        serviceName,                // 要安装的服务的名称
        serviceName,                // 用户界面程序用来标识服务的显示名称
        SERVICE_ALL_ACCESS,         // 对服务的访问权限：所有全权限
        SERVICE_KERNEL_DRIVER,      // 服务类型：驱动服务
        SERVICE_DEMAND_START,       // 服务启动选项：进程调用 StartService 时启动
        SERVICE_ERROR_IGNORE,       // 如果无法启动：忽略错误继续运行
        drvPath,                    // 驱动文件绝对路径，如果包含空格需要多加双引号
        NULL,                       // 服务所属的负载订购组：服务不属于某个组
        NULL,                       // 接收订购组唯一标记值：不接收
        NULL,                       // 服务加载顺序数组：服务没有依赖项
        NULL,                       // 运行服务的账户名：使用 LocalSystem 账户
        NULL                        // LocalSystem 账户密码
    );
    if (schService == NULL) {
        CloseServiceHandle(schSCManager);
        return FALSE;
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return TRUE;
}

BOOL SysLauncher::startDvr()
{
    InitConsoleWindow(true);
    // 打开服务控制管理器数据库
    SC_HANDLE schSCManager = OpenSCManager(
        NULL,                   // 目标计算机的名称,NULL：连接本地计算机上的服务控制管理器
        NULL,                   // 服务控制管理器数据库的名称，NULL：打开 SERVICES_ACTIVE_DATABASE 数据库
        SC_MANAGER_ALL_ACCESS   // 所有权限
    );
    if (schSCManager == NULL) {

        return FALSE;
    }

    // 打开服务
    SC_HANDLE hs = OpenServiceA(
        schSCManager,           // 服务控件管理器数据库的句柄
        serviceName,            // 要打开的服务名
        SERVICE_ALL_ACCESS      // 服务访问权限：所有权限
    );
    if (hs == NULL) {
        CloseServiceHandle(schSCManager);
        return FALSE;
    }
    if (StartService(hs, 0, 0) == 0) {
        CloseServiceHandle(hs);
        CloseServiceHandle(schSCManager);
        return FALSE;
    }


    CloseServiceHandle(hs);
    CloseServiceHandle(schSCManager);
    return TRUE;
}

BOOL SysLauncher::stopDvr()
{

    // 打开服务控制管理器数据库
    SC_HANDLE schSCManager = OpenSCManager(
        NULL,                   // 目标计算机的名称,NULL：连接本地计算机上的服务控制管理器
        NULL,                   // 服务控制管理器数据库的名称，NULL：打开 SERVICES_ACTIVE_DATABASE 数据库
        SC_MANAGER_ALL_ACCESS   // 所有权限
    );
    if (schSCManager == NULL) {
        return FALSE;
    }

    // 打开服务
    SC_HANDLE hs = OpenServiceA(
        schSCManager,           // 服务控件管理器数据库的句柄
        serviceName,            // 要打开的服务名
        SERVICE_ALL_ACCESS      // 服务访问权限：所有权限
    );
    if (hs == NULL) {
        CloseServiceHandle(schSCManager);
        return FALSE;
    }

    // 如果服务正在运行
    SERVICE_STATUS status;
    if (QueryServiceStatus(hs, &status) == 0) {
        CloseServiceHandle(hs);
        CloseServiceHandle(schSCManager);
        return FALSE;
    }
    if (status.dwCurrentState != SERVICE_STOPPED &&
        status.dwCurrentState != SERVICE_STOP_PENDING
        ) {
        // 发送关闭服务请求
        if (ControlService(
            hs,                         // 服务句柄
            SERVICE_CONTROL_STOP,       // 控制码：通知服务应该停止
            &status                     // 接收最新的服务状态信息
        ) == 0) {
            CloseServiceHandle(hs);
            CloseServiceHandle(schSCManager);
            return FALSE;
        }

        // 判断超时
        INT timeOut = 0;
        while (status.dwCurrentState != SERVICE_STOPPED) {
            timeOut++;
            if (QueryServiceStatus(hs, &status)) {

            };
            Sleep(50);
        }
        if (timeOut > 80) {
            CloseServiceHandle(hs);
            CloseServiceHandle(schSCManager);
            return FALSE;
        }
    }

    CloseServiceHandle(hs);
    CloseServiceHandle(schSCManager);
    return TRUE;
}

BOOL SysLauncher::unloadDvr()
{

    // 打开服务控制管理器数据库
    SC_HANDLE schSCManager = OpenSCManager(
        NULL,                   // 目标计算机的名称,NULL：连接本地计算机上的服务控制管理器
        NULL,                   // 服务控制管理器数据库的名称，NULL：打开 SERVICES_ACTIVE_DATABASE 数据库
        SC_MANAGER_ALL_ACCESS   // 所有权限
    );
    if (schSCManager == NULL) {
        return FALSE;
    }

    // 打开服务
    SC_HANDLE hs = OpenServiceA(
        schSCManager,           // 服务控件管理器数据库的句柄
        serviceName,            // 要打开的服务名
        SERVICE_ALL_ACCESS      // 服务访问权限：所有权限
    );
    if (hs == NULL) {
        CloseServiceHandle(schSCManager);
        return FALSE;
    }

    // 删除服务
    if (DeleteService(hs) == 0) {
        CloseServiceHandle(hs);
        CloseServiceHandle(schSCManager);
        return FALSE;
    }

    CloseServiceHandle(hs);
    CloseServiceHandle(schSCManager);
    return TRUE;
}

void SysLauncher::connectToIoDevice()
{
    hDevice = ::CreateFileA(SYMBOL_LINK,

      GENERIC_READ | GENERIC_WRITE,

      0,

      NULL,

      OPEN_EXISTING,

      FILE_ATTRIBUTE_NORMAL,

      NULL);

    if (hDevice == INVALID_HANDLE_VALUE)

    {

        printf("Failed to Open Device : %d\n", ::GetLastError());

        return;

    }
    MY_ANYTYPE_IOARG data = { 0 };
    data.value.active_process.pid = (HANDLE)GetCurrentProcessId();
    data.optioncode = 'CON';
    if (launcher->controlIoDevice(CTL_CODE_DEBUG, &data)) {
        printf("success upload cheatengine pid to my driver\r\n");
    }
    
}
ULONG_PTR ForceFindJumpCode(HANDLE nowProcess, ULONG_PTR begin_addr, ULONG SizeOfImage) {

    if (!begin_addr)return 0;
    ULONG_PTR offset_addr = 0;
    NTSTATUS ntStatus;

    UCHAR prechar = 0x00;
    UCHAR nowchar = 0x00;
    while (offset_addr < SizeOfImage) {

        __try
        {

            UCHAR buffer[1024] = { 0 };
            size_t read_len = 0;
            if ((*Exported.ReadProcessMemory)(nowProcess, (LPCVOID)(offset_addr + begin_addr), buffer, 1024, &read_len)) {
                for (int i = 0; i < read_len; i++) {
                    nowchar = buffer[i] & 0xFF;
                    if (prechar == (UCHAR)0xEB && nowchar == (UCHAR)0xFE) {//0xEB 0xFE jmp 到自己
                        printf("Good We find at: 0x%llx\n", begin_addr + offset_addr + i - 1);
                        return begin_addr + offset_addr + i - 1;
                    }
                    else {
                        prechar = nowchar;

                    }

                }

            }
            else {
                printf("Failt To Touch at: 0x%llx\n", offset_addr + begin_addr);
                break;
            }

        }
        __except (1)
        {
            printf("[ERROR]UnKown Error at: 0x%llx\n", offset_addr + begin_addr);
            prechar = 0x00;
            nowchar = 0x00;
        };
        offset_addr += 1024;
    }
    return 0;



}
void SysLauncher::GetProcessThreads() {
  

    HANDLE nowProcess = *Exported.OpenedProcessHandle;
    HMODULE ntdll = ProCntrl::GetModule(nowProcess, "ntdll");

    this->intCCaddr = 0;
    char s[200];
    
    


    //PVOID record = addScriptToTable("FakeNtDll", s, NULL);
    //luaRecordSetActive(record, true);
  /*  if (false) {
       
    }*/

    MODULEINFO moduleInfo;
    if (GetModuleInformation(nowProcess, ntdll, &moduleInfo, sizeof(moduleInfo))) {
        std::cout << "目标DLL的内存地址：" << moduleInfo.lpBaseOfDll << std::endl;
    }

    if (false) {
        char buffer[0x20];
        size_t read_len = 0;
        __int64 startAddr = ProCntrl::EnumModuleExportFunction(nowProcess, ntdll, "TpSetTimer", false);//随便找一个int 3指令
        (*Exported.ReadProcessMemory)(nowProcess, (LPCVOID)startAddr, buffer, 0x20, &read_len);
        printf("CONNECT startAddr:0x%llx\r\n", (__int64)startAddr);
        for (int i = 0; i < read_len; i++) {
            if ((buffer[i] & 0xff) == 0xCC) this->intCCaddr = startAddr + i;
            printf("READ BUFFER :0x%x\r\n", buffer[i] & 0xff);
        }
        char buffer2[2] = { 0xEB,0xFE }; //jmp到自己的死循环
        size_t write_len;
        (*Exported.WriteProcessMemory)(nowProcess, (LPCVOID)this->intCCaddr, buffer2, 2, &write_len);
    }
    else {
        this->intCCaddr = ForceFindJumpCode(nowProcess, (ULONG_PTR)moduleInfo.lpBaseOfDll, moduleInfo.SizeOfImage);
    }
   


    sprintf(s, "registerSymbol('fakeNtdll',0x%llx)", this->intCCaddr);
    luaLoadString(s);
    /*
    this->intCCaddr = luaAllocateMemory(5, 0, false);
    __int64 vtdll = luaGetAddress("VTDebugerDll.dll"); //ProCntrl::GetModule(nowProcess, "VTDebugerDll");
    byte buffer[0x1000 * 100];
    size_t read_len;
    (*Exported.ReadProcessMemory)(nowProcess, (LPCVOID)vtdll, buffer, 0x1000 * 100, &read_len);
    __int64 tempaddr = ProCntrl::EnumModuleExportFunction((HMODULE)buffer, "asm_break_point", false);
    launcher->intCCaddr = tempaddr - (__int64)buffer;
    printf("CONNECT BP Offset:0x%llx\r\n", (__int64)launcher->intCCaddr);
    this->intCCaddr = this->intCCaddr + (__int64)vtdll;
   
    */

    printf("CONNECT CC:0x%llx\r\n", this->intCCaddr);

   
    //if (dwProcess)CloseHandle(dwProcess); 进程句柄交给CE自动关闭
    //if (dwThread)CloseHandle(dwThread);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot failed" << std::endl;
        return;
    }
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    this->dwProcess = *Exported.OpenedProcessHandle;
    this->dwProcessId = *Exported.OpenedProcessID;
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == this->dwProcessId) {
                std::cout << "Thread ID: " << te32.th32ThreadID << std::endl;
                dwThreadIds.push_back(te32.th32ThreadID);
              
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    // 关闭快照句柄
    CloseHandle(hSnapshot);
}
void SysLauncher::closeIoDevice()
{

    if (this->intCCaddr) {
        luaLoadString("unregisterSymbol('fakeNtdll')");
        luaDeAlloc(this->intCCaddr);
    }

    InitConsoleWindow(false);
    if (hDevice != INVALID_HANDLE_VALUE)

    {
        CloseHandle(hDevice); 
    }
}

BOOL SysLauncher::controlIoDevice(DWORD dwIoControlCode, PMY_ANYTYPE_IOARG anyTypeInput)
{
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("Failed to Open Device\n");

        return FALSE;
    }

    DWORD dwOutput;  // 注意这里input也是output是同一个内存区域。
    BOOL bRet = ::DeviceIoControl(hDevice,dwIoControlCode, anyTypeInput, sizeof(MY_ANYTYPE_IOARG), anyTypeInput, sizeof(MY_ANYTYPE_IOARG), &dwOutput, NULL);

    anyTypeInput->ret_size = dwOutput;
    return bRet;
}

void SysLauncher::resetEnviroment()
{
    runStage = 0;
    dwProcess = NULL;
    nowThreadIndex = 0;
    currentThread = NULL;
    dwProcessId = NULL;
    dwThreadIds.clear();
    exThreadId = 0;
    exThreadDr6 = 0;
    RFValue = 0;
    intCCaddr = 0;
    pre_debug_rip = 0;
}

SysLauncher::~SysLauncher()
{

    if (stopDvr() == TRUE) {
        printf("stopDvr success.\n");
    }
    if (unloadDvr() == TRUE) {
        printf("unloadDvr success.\n");
    }
    //if (!CloseHandle(this->eventSignal))  printf("事件句柄关闭失败");
}
//必须手动挂起，正常windows线程异常会自动挂起线程，但是由于使用了VT拦截了所有异常，因此线程默认不会挂起需要手动操作
void suspendAndRecordCurrentThread(DWORD threadId) {

    launcher->currentThread = (*Exported.OpenThread)(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, TRUE, threadId);
    DWORD  ret = 0;
    ret = (*Exported.SuspendThread)(launcher->currentThread);
    while (ret < 0) {
        printf("SuspendThread Error %d\n", GetLastError());
        ret = (*Exported.SuspendThread)(launcher->currentThread);
    }

}

BOOL VTSetThreadContext(HANDLE hThread, CONST CONTEXT* lpContext) {

    if (launcher->exThreadDr6 && launcher->exThreadId) {
        if (GetThreadId(hThread) == launcher->exThreadId) {//模拟CE修改DR6或RF两个寄存器的相互影响
            ULONG rflagMask = (1 << 16);
            if (launcher->pre_debug_rip != lpContext->Rip) {
                printf("[ERROR] CE do not restore rip to orgin 0x%llx => 0x%llx\n", lpContext->Rip, launcher->pre_debug_rip);
            }
            if (lpContext->ContextFlags & CONTEXT_DEBUG_REGISTERS) {//模拟CE对于DR6的修改，以及修改DR6对RF位造成的间接影响
                launcher->exThreadDr6 = lpContext->Dr6; //记住来自CE对于Dr6的修改
                if (launcher->exThreadDr6 == 0 || launcher->exThreadDr6 == 0x0ff0) {//如果是取消DR6的命令，则需要模拟一个RF标志位
                    CONTEXT tmpContext;
                    memcpy(&tmpContext, lpContext, sizeof(CONTEXT));//复制CE提交的线程上下文
                    tmpContext.EFlags |= rflagMask;//模拟一个RF交给VT防止阻塞
                    return SetThreadContext(hThread, &tmpContext);
                }

            }
            ULONG rflagValue = lpContext->EFlags & rflagMask;
            if (rflagValue) {//模拟CE设置RF时，对于DR6产生的间接影响(造成DR6清零)
                launcher->RFValue = rflagValue;
                launcher->exThreadDr6 = 0;//假装清零
            }

           
        }
        else if (lpContext->ContextFlags & CONTEXT_DEBUG_REGISTERS) {
            ULONG tf = lpContext->EFlags& (1 << 8);
            if (tf)  printf("[ERROR] CE set other thread TF=1");
        }
    }
    BOOL success = SetThreadContext(hThread, lpContext);
    return success;
}
BOOL VTGetThreadContext( HANDLE hThread,  LPCONTEXT lpContext) {
    BOOL success = GetThreadContext(hThread, lpContext);
    if (launcher == NULL) {
        printf("[THREAD][%x] 0x%x", GetThreadId(hThread), (ULONG)hThread);
        return success;
    }
   
    if (success && launcher->exThreadId) {
        /*因为CE会先在HandleDebugEvent 的 if BPOverride then 中删除所有断点后，再重新设置
           * 所以rflag有效时不能把Dr6标记为异常，否则CE不会修改再修改上下文，导致所有断点都被删除
           */
        if (GetThreadId(hThread) == launcher->exThreadId) { //确认是否为当前发生异常的线程，千万不要动其他线程的上下文，会造成线程永久阻塞的恶性bug
            if (lpContext->Rip == launcher->intCCaddr) lpContext->Rip = launcher->pre_debug_rip;//返回假的RIP
            else if(lpContext->Rip != launcher->pre_debug_rip)  printf("[ERROR][THREAD][%x] fail to build fake rip 0x%llx --> 0x%llx\n", GetThreadId(hThread), lpContext->Rip, launcher->pre_debug_rip);
            lpContext->Dr6 = launcher->exThreadDr6;//用自己模拟的DR6替换原始值
        }
        else if (lpContext->ContextFlags & CONTEXT_DEBUG_REGISTERS) {
            ULONG tf = lpContext->EFlags & (1 << 8);
            if (tf)  printf("[ERROR] CE find other thread TF=1");
        }
    }

    return success;

}
//测试地址 00482003
BOOL VTDebugActiveProcess(DWORD dwProcessId)
{
    if (launcher == NULL)return FALSE;
    // 相对路径
    const char* relativePath = "VTDebugerDll.dll";
    // 缓冲区用于存储绝对路径
    char absolutePath[MAX_PATH];
    DWORD result = GetFullPathName(relativePath, MAX_PATH, absolutePath, NULL);
    launcher->resetEnviroment();
    launcher->runStage = 0; //设置状态机为初始状态
    launcher->GetProcessThreads();//遍历线程，并注册shellcode或者查找int CC指令

    if (launcher->intCCaddr == 0) {
        printf("can not find any CC instruction in process!!!\r\n");
        return FALSE;
    }
    MY_ANYTYPE_IOARG data = { 0 };
    data.value.active_process.intCCaddr = launcher->intCCaddr;
    data.needWait = 0;
    data.optioncode = 'DAP';
    data.dwProcessId = (HANDLE)dwProcessId;
    data.value.active_process.pid = (HANDLE)GetCurrentProcessId();
    launcher->controlIoDevice(CTL_CODE_DEBUG, &data);
    if (data.ret_size > 0) return TRUE;
    return FALSE;
}
//CE中设置断点的回调函数，下断点时通知VT注册响应断点，从而实现白名单异常过滤，有效防止调试陷阱
BOOL VTChangeRegOnBP(ULONG_PTR address, BOOL remove) {
    if (launcher == NULL)  return FALSE;
    //if (launcher->runStage < 2) return FALSE; //TO DO:遍历线程和创建进程时不注册异常 (这导致直接启动调试器无法正常工作，这个留在之后再优化)
    
    MY_ANYTYPE_IOARG data = { 0 };
    data.needWait = 0;
    data.optioncode = 'SBP';
    data.dwDebugEventCode = 0;
    data.value.simple_debug_event.ExceptionAddress = (PVOID)address;
    data.value.simple_debug_event.dwFirstChance = !remove;//如果需要移除断点(remove=1)，则设置为dwFirstChance=0，否则设置为dwFirstChance=1
    if (launcher->controlIoDevice(CTL_CODE_DEBUG, &data)) return TRUE;
    printf("[FAIL TO ADD]address 0x%llx,remove:%d\n", address, remove);
    return FALSE;

}
BOOL VTContinueDebugEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus) {
    if (dwContinueStatus == DBG_EXCEPTION_NOT_HANDLED) { //如果CE没有成功处理异常，就靠我们自己来处理
        CONTEXT context = { 0 };
        ULONG rflagMask = (1 << 16);
        HANDLE hThread = (*Exported.OpenThread)(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, TRUE, dwThreadId);

        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(hThread, &context); 
        printf("[CONTINUE ERROR][Thread]dw:[%x]ex:[%x] no handle  Rip = 0x%llx exceptionRip = 0x%llx\n", dwThreadId, launcher->exThreadId, context.Rip, launcher->pre_debug_rip);
        context.Rip = launcher->pre_debug_rip;//将RIP重新路由到原始位置，并设置RF位=1
        context.EFlags |= rflagMask;//为了让事件继续模拟一个RF交给VT防止阻塞
        SetThreadContext(hThread, &context);
        CloseHandle(hThread);
    }
    MY_ANYTYPE_IOARG data = { 0 };
    data.needWait = 0;
    data.optioncode = 'CDE';
    data.dwDebugEventCode = 0;
    launcher->exThreadId = 0;//将异常的线程号设置为空
    launcher->exThreadDr6 = 0;//模拟的DR6寄存器设置为0
    data.value.simple_debug_event.dwFirstChance = (dwContinueStatus!=DBG_EXCEPTION_NOT_HANDLED);//如果CE接管了异常则是第一次尝试，否则通知内核已经尝试了两次

    if (launcher->controlIoDevice(CTL_CODE_DEBUG, &data)) {//手动将线程重启，没重启则反复尝试并打印错误码。
        if (launcher->currentThread) {
            DWORD  ret = 0;
            ret = (*Exported.ResumeThread)(launcher->currentThread);
            while (ret < 0) {
                printf("ResumeThread Error %d\n", GetLastError());
                ret = (*Exported.ResumeThread)(launcher->currentThread);
            }
            
            CloseHandle(launcher->currentThread);
        }
        return TRUE;

    }
    return FALSE;
}




BOOL VTWaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds) {
    lpDebugEvent->dwDebugEventCode = 0;//send unknown excpation to ce


    MY_ANYTYPE_IOARG data = { 0 };
    data.needWait = dwMilliseconds * 10;
    data.optioncode = 'WDE';
    data.dwDebugEventCode = 0;
    if (launcher->runStage == 0) { //模拟 CREATE_PROCESS事件
        printf("SEND FAKE CREATE_PROCESS_DEBUG_EVENT\r\n");
        data.dwDebugEventCode = CREATE_PROCESS_DEBUG_EVENT;
        if (launcher->controlIoDevice(CTL_CODE_DEBUG, &data)) {
            if (data.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
                printf("FAKE CREATE_PROCESS_DEBUG_EVENT SEND OVER\r\n");
                launcher->runStage = 1;
                DWORD threadId = launcher->dwThreadIds[0];//默认使用列表中第一个线程
                lpDebugEvent->dwDebugEventCode = data.dwDebugEventCode;
                lpDebugEvent->dwProcessId = (ULONG)data.dwProcessId; //只有id用内核的其他都用R3的
                lpDebugEvent->dwThreadId = (ULONG)threadId;//默认使用列表中第一个线程

                lpDebugEvent->u.CreateProcessInfo.hFile = 0;
                lpDebugEvent->u.CreateProcessInfo.dwDebugInfoFileOffset = 0;
                lpDebugEvent->u.CreateProcessInfo.fUnicode = 1;
                lpDebugEvent->u.CreateProcessInfo.hProcess = launcher->dwProcess;
                lpDebugEvent->u.CreateProcessInfo.hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
                lpDebugEvent->u.CreateProcessInfo.lpBaseOfImage = (PVOID)0x123456; //通知CE这是假的调试事件，直接激活UI否则会一直等待
                lpDebugEvent->u.CreateProcessInfo.lpImageName = 0;
                lpDebugEvent->u.CreateProcessInfo.lpStartAddress = 0;
                lpDebugEvent->u.CreateProcessInfo.lpThreadLocalBase = 0;
                lpDebugEvent->u.CreateProcessInfo.nDebugInfoSize = 0;
                launcher->nowThreadIndex = 1;
                suspendAndRecordCurrentThread(lpDebugEvent->dwThreadId);
                return TRUE;

            }
        }

    }

    if (launcher->runStage == 1) {//模拟CREATE_THREAD事件
        
        if (launcher->nowThreadIndex > 0 && launcher->nowThreadIndex < launcher->dwThreadIds.size()) {
            DWORD threadId = launcher->dwThreadIds[launcher->nowThreadIndex];
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
            if (hThread == NULL) {
                std::cerr << "OpenThread failed for thread ID: " << threadId << std::endl;
            }
            else {
                std::cout << "Opened thread handle: " << hThread << std::endl;
                lpDebugEvent->dwDebugEventCode = CREATE_THREAD_DEBUG_EVENT;
                lpDebugEvent->dwProcessId = launcher->dwProcessId;
                lpDebugEvent->dwThreadId = threadId;
                lpDebugEvent->u.CreateThread.hThread = hThread;
                lpDebugEvent->u.CreateThread.lpStartAddress = 0;
                lpDebugEvent->u.CreateThread.lpThreadLocalBase = 0;
                lpDebugEvent->dwThreadId = (ULONG)threadId;
                suspendAndRecordCurrentThread(lpDebugEvent->dwThreadId);

            }

            launcher->nowThreadIndex++;
            return TRUE;

        }
        else {
            launcher->runStage = 2;//将状态机调整为最后阶段，可以开始处理VT中的异常
        }
    }
   
   
    if (launcher->controlIoDevice(CTL_CODE_DEBUG, &data)) {

        if (data.value.simple_debug_event.ExceptionAddress != 0) {
            launcher->pre_debug_rip = (__int64)data.value.simple_debug_event.ExceptionAddress;
            lpDebugEvent->dwDebugEventCode = data.dwDebugEventCode;
            lpDebugEvent->dwProcessId = (ULONG)data.dwProcessId;
            lpDebugEvent->dwThreadId = (ULONG)data.dwThreadId;
            launcher->exThreadId = lpDebugEvent->dwThreadId;
            suspendAndRecordCurrentThread(lpDebugEvent->dwThreadId);
            //检查VT异常是否有效，无效则直接忽略异常，并在控制台输出错误代码
            CONTEXT threadContext = {0};
            threadContext.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(launcher->currentThread, &threadContext)) {
                if (threadContext.Rip != launcher->intCCaddr) {
                    printf("[WAIT ERROR][THREAD]dw:[%x] Error Debug evet from vt dr6 = 0x%llx dr7 = 0x%llx Eflags = 0x%x rip = 0x%llx\n", lpDebugEvent->dwThreadId, threadContext.Dr6,threadContext.Dr7,threadContext.EFlags, threadContext.Rip);
                    VTContinueDebugEvent(lpDebugEvent->dwProcessId, lpDebugEvent->dwThreadId, DBG_CONTROL_C);
                    return FALSE;
                }
            }
            launcher->exThreadDr6 = data.value.simple_debug_event.ExceptionInformation[0];//实测没有产生中断的情况下，无法直接更改dr6，因此这里使用成员变量来模拟Dr6变化
            launcher->RFValue = 0;//记录一下当前线程的RF位，默认应该位0
            lpDebugEvent->u.Exception.ExceptionRecord.ExceptionFlags = 0;
            lpDebugEvent->u.Exception.ExceptionRecord.NumberParameters = 0;
            lpDebugEvent->u.Exception.ExceptionRecord.ExceptionRecord = NULL;
            lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode = EXCEPTION_SINGLE_STEP;//这个版本默认只处理硬件寄存器断点。注意这个STEP不是单步的意思，就是硬件异常
            lpDebugEvent->u.Exception.dwFirstChance = 1;
            lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress = data.value.simple_debug_event.ExceptionAddress;//记录RIP

            return TRUE;

        }
    }
    
    return FALSE;

}

BOOL
//use 	*Exported.ReadProcessMemory = MyReadProcessMemory Hook CE API
__stdcall
MyReadProcessMemory(
    HANDLE hProcess,
    LPCVOID lpBaseAddress,
    LPVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesRead
)
{
    char* buff = (char*)lpBuffer;
    for (int i = 0; i < nSize; i++)
    {
        buff[i] = 0x90;
    }
    *lpNumberOfBytesRead = nSize;
    return true;
}
