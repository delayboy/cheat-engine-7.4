unit KernelDebuggerInterface;

{$mode delphi}

interface

{$ifdef windows}
uses
  jwawindows, windows, Classes, SysUtils,cefuncproc, newkernelhandler,DebuggerInterface,contnrs;

type
  TEventType=(etCreateProcess, etCreateThread, etDestroyThread);
  TInjectedEvent=record
    eventType: TEventType;
    processid: dword;
    threadid: dword;
  end;
  PInjectedEvent=^TInjectedEvent;


type
  TKernelDebugInterface=class;
  TThreadPoller=class(tthread)
  private
    threadlist: TList;

    procedure UpdateList;
    procedure CreateThreadEvent(threadid: dword);
    procedure DestroyThreadEvent(threadid: dword);

  public
    pid: dword;
    di: TKernelDebugInterface;
    procedure GetCurrentList(list: tlist);
    procedure execute; override;
  end;

  TKernelDebugInterface=class(TDebuggerInterface)
  private
    pid: DWORD;
    currentdebuggerstate: TDebuggerstate;

    injectedEvents: Tqueue;
    threadpoller: TThreadPoller;
    NeedsToContinue: boolean;
    globalDebug: boolean;
  public
    function WaitForDebugEvent(var lpDebugEvent: TDebugEvent; dwMilliseconds: DWORD): BOOL; override;
    function ContinueDebugEvent(dwProcessId: DWORD; dwThreadId: DWORD; dwContinueStatus: DWORD): BOOL; override;
    function SetThreadContext(hThread: THandle; const lpContext: TContext; isFrozenThread: Boolean=false): BOOL; override;
    function GetThreadContext(hThread: THandle; var lpContext: TContext; isFrozenThread: Boolean=false):  BOOL; override;

    function GetLastBranchRecords(lbr: pointer): integer; override;
    function canReportExactDebugRegisterTrigger: boolean; override;

    procedure injectEvent(e: pointer);
    function DebugActiveProcess(dwProcessId: DWORD): WINBOOL; override;
    function EventCausedByDBVM: boolean;

    destructor destroy; override;
    constructor create(globalDebug, canStepKernelcode: boolean);
  end;

{$endif}

implementation

{$ifdef windows}

uses symbolhandler, ProcessHandlerUnit, dialogs;

resourcestring
  rsDBKDebug_StartDebuggingFailed ='DBKDebug_StartDebugging failed';
  rsKernelModeNeedsDBVM = 'You can''t use kerneldebug in 64-bit without DBVM';

procedure TThreadPoller.CreateThreadEvent(threadid: dword);
var ie: PInjectedEvent;
begin
  getmem(ie, sizeof(TInjectedEvent));
  ie.eventType:=etCreateThread;
  ie.threadid:=threadid;
  ie.processid:=pid;

  di.injectEvent(ie);
end;

procedure TThreadPoller.DestroyThreadEvent(threadid: dword);
var ie: PInjectedEvent;
begin
  getmem(ie, sizeof(TInjectedEvent));
  ie.eventType:=etDestroyThread;
  ie.threadid:=threadid;
  ie.processid:=pid;

  di.injectEvent(ie);
end;


procedure TThreadPoller.GetCurrentList(list: tlist);
var
  ths: thandle;
  lpte: TThreadEntry32;
  check: boolean;
begin
  ths:=CreateToolhelp32Snapshot(TH32CS_SNAPALL,pid);

  if ths<>INVALID_HANDLE_VALUE then
  begin
    zeromemory(@lpte,sizeof(lpte));
    lpte.dwSize:=sizeof(lpte);
    check:=Thread32First(ths, lpte);
    while check do
    begin
      if lpte.th32OwnerProcessID=pid then
        list.add(pointer(ptrUint(lpte.th32ThreadID)));

      check:=Thread32next(ths,lpte);
    end;

    closehandle(ths);
  end;
end;

procedure TThreadPoller.UpdateList;
var newlist: Tlist;
i: integer;
begin
  newlist:=tlist.create;
  GetCurrentList(newlist);

  //now try to find the differences

  //is there a threadid that's not in the current threadlist?
  for i:=0 to newlist.Count-1 do
    if threadlist.IndexOf(newlist[i])=-1 then //not found
      CreateThreadEvent(ptrUint(newlist[i]));

  for i:=0 to threadlist.count-1 do
    if newlist.IndexOf(threadlist[i])=-1 then //the new list doesn't contain this threadid
      DestroyThreadEvent(ptrUint(threadlist[i]));

  //free the old list and make the new list the current list
  threadlist.free;
  threadlist:=newlist;
end;

procedure TThreadPoller.execute;
begin
  threadlist:=TList.Create;
  try
    GetCurrentList(threadlist);

    while not terminated do
    begin

      sleep(1000);
      UpdateList;
    end;
  finally
    threadlist.free;
  end;
end;



//------------------------------------------------------------------------------

procedure TKernelDebugInterface.injectEvent(e: pointer);
begin
  if injectedEvents<>nil then
    injectedEvents.Push(e);
end;

function TKernelDebugInterface.DebugActiveProcess(dwProcessId: DWORD): WINBOOL;
{Start the kerneldebugger for the current process}
var cpe: PInjectedEvent;
    tl: tlist;
    i: integer;
begin
  loaddbk32;
  //if not loaddbvmifneeded then
  //  raise exception.Create('You can''t currently use the kernel debugger');

  outputdebugstring('Using the kernelmode debugger');

  result:=DBKDebug_StartDebugging(dwProcessId);

  if result then
  begin
    if processhandler.processid<>dwProcessId then
    begin
      processhandler.processid:=dwProcessID;
      Open_Process;
      symhandler.reinitialize;
      symhandler.waitforsymbolsloaded(true);
    end;

    pid:=dwProcessID;

    threadpoller:=TThreadPoller.Create(true);
    threadpoller.pid:=pid;

    tl:=tlist.create;
    try
      threadpoller.GetCurrentList(tl);

      getmem(cpe, sizeof(TInjectedEvent));
      cpe.eventType:=etCreateProcess;
      cpe.processid:=pid;
      if tl.count>0 then
        cpe.threadid:=ptrUint(tl.items[0])
      else
        cpe.threadid:=0;

      injectEvent(cpe);

      for i:=0 to tl.count-1 do
      begin
        getmem(cpe, sizeof(TInjectedEvent));
        cpe.eventType:=etCreateThread;
        cpe.processid:=pid;
        cpe.threadid:=ptrUint(tl.items[i]);
        injectEvent(cpe);
      end;


    finally
      tl.free;
    end;


    threadpoller.Start;
  end
  else
    raise exception.create(rsDBKDebug_StartDebuggingFailed);


end;

function TKernelDebugInterface.SetThreadContext(hThread: THandle; const lpContext: TContext; isFrozenThread: Boolean=false): BOOL;
var
  myContext: TContext;
  myThread : HANDLE;
begin
  outputdebugstring('TKernelDebugInterface.SetThreadContext');
  if NeedsToContinue and isFrozenThread then
  begin
    //myThread := newkernelhandler.OpenThread(THREAD_SUSPEND_RESUME or THREAD_GET_CONTEXT or THREAD_SET_CONTEXT,true,GetThreadId(hThread));
    //newkernelhandler.SuspendThread(myThread);
    //use the currentdebuggerstate
    currentdebuggerstate.threadid:=GetThreadId(hThread);
    currentdebuggerstate.eax:=lpContext.{$ifdef cpu64}Rax{$else}eax{$endif};
    currentdebuggerstate.ebx:=lpContext.{$ifdef cpu64}Rbx{$else}ebx{$endif};
    currentdebuggerstate.ecx:=lpContext.{$ifdef cpu64}Rcx{$else}ecx{$endif};
    currentdebuggerstate.edx:=lpContext.{$ifdef cpu64}Rdx{$else}edx{$endif};
    currentdebuggerstate.esi:=lpContext.{$ifdef cpu64}Rsi{$else}esi{$endif};
    currentdebuggerstate.edi:=lpContext.{$ifdef cpu64}Rdi{$else}edi{$endif};
    currentdebuggerstate.ebp:=lpContext.{$ifdef cpu64}Rbp{$else}ebp{$endif};
    currentdebuggerstate.esp:=lpContext.{$ifdef cpu64}Rsp{$else}esp{$endif};
    currentdebuggerstate.eip:=lpContext.{$ifdef cpu64}Rip{$else}eip{$endif};
    {$ifdef cpu64}
    currentdebuggerstate.r8:=lpContext.r8;
    currentdebuggerstate.r9:=lpContext.r9;
    currentdebuggerstate.r10:=lpContext.r10;
    currentdebuggerstate.r11:=lpContext.r11;
    currentdebuggerstate.r12:=lpContext.r12;
    currentdebuggerstate.r13:=lpContext.r13;
    currentdebuggerstate.r14:=lpContext.r14;
    currentdebuggerstate.r15:=lpContext.r15;
    {$endif}
    currentdebuggerstate.cs:=lpContext.SegCs;
    currentdebuggerstate.ss:=lpContext.SegSs;
    currentdebuggerstate.ds:=lpContext.SegDs;
    currentdebuggerstate.es:=lpContext.SegEs;
    currentdebuggerstate.fs:=lpContext.SegFs;
    currentdebuggerstate.gs:=lpContext.SegGs;
    currentdebuggerstate.eflags:=lpContext.EFlags;

    if not globalDebug then
    begin
      currentdebuggerstate.dr0:=lpContext.Dr0;
      currentdebuggerstate.dr1:=lpContext.Dr1;
      currentdebuggerstate.dr2:=lpContext.Dr2;
      currentdebuggerstate.dr3:=lpContext.Dr3;
      currentdebuggerstate.dr6:=lpContext.Dr6;
      currentdebuggerstate.dr7:=lpContext.Dr7;
    end;

    {$ifdef cpu64}

    CopyMemory(@currentdebuggerstate.fxstate, @lpContext.FltSave, 512);
    {$else}
    CopyMemory(@currentdebuggerstate.fxstate, @lpContext.ext, sizeof(lpContext.ext));
    {$endif}
    CopyMemory(@myContext, @lpContext, sizeof(lpContext));
    if DBKDebug_SetDebuggerState(@currentdebuggerstate)then
    begin
       //我修改的部分运行完内核更新后直接调用KERNEL设置线程寄存器
      myContext.{$ifdef cpu64}Rax{$else}eax{$endif}:=currentdebuggerstate.eax;
      myContext.{$ifdef cpu64}Rbx{$else}ebx{$endif}:=currentdebuggerstate.ebx;
      myContext.{$ifdef cpu64}Rcx{$else}ecx{$endif}:=currentdebuggerstate.ecx;
      myContext.{$ifdef cpu64}Rdx{$else}edx{$endif}:=currentdebuggerstate.edx;
      myContext.{$ifdef cpu64}Rsi{$else}esi{$endif}:=currentdebuggerstate.esi;
      myContext.{$ifdef cpu64}Rdi{$else}edi{$endif}:=currentdebuggerstate.edi;
      myContext.{$ifdef cpu64}Rbp{$else}ebp{$endif}:=currentdebuggerstate.ebp;
      myContext.{$ifdef cpu64}Rsp{$else}esp{$endif}:=currentdebuggerstate.esp;
      myContext.{$ifdef cpu64}Rip{$else}eip{$endif}:=currentdebuggerstate.eip;
      {$ifdef cpu64}
      myContext.r8:=currentdebuggerstate.r8;
      myContext.r9:=currentdebuggerstate.r9;
      myContext.r10:=currentdebuggerstate.r10;
      myContext.r11:=currentdebuggerstate.r11;
      myContext.r12:=currentdebuggerstate.r12;
      myContext.r13:=currentdebuggerstate.r13;
      myContext.r14:=currentdebuggerstate.r14;
      myContext.r15:=currentdebuggerstate.r15;
      {$endif}
      myContext.SegCs:=currentdebuggerstate.cs;
      myContext.SegSs:=currentdebuggerstate.ss;
      myContext.SegDs:=currentdebuggerstate.ds;
      myContext.SegEs:=currentdebuggerstate.es;
      myContext.SegFs:=currentdebuggerstate.fs;
      myContext.SegGs:=currentdebuggerstate.gs;
      myContext.EFlags:=currentdebuggerstate.eflags;
      myContext.Dr0:=currentdebuggerstate.dr0;
      myContext.Dr1:=currentdebuggerstate.dr1;
      myContext.Dr2:=currentdebuggerstate.dr2;
      myContext.Dr3:=currentdebuggerstate.dr3;
      myContext.Dr6:=currentdebuggerstate.dr6;
      myContext.Dr7:=currentdebuggerstate.dr7;


      {$ifdef cpu64}
      CopyMemory(@myContext.FltSave, @currentdebuggerstate.fxstate, 512);
      {$else}
      CopyMemory(@myContext.ext, @currentdebuggerstate.fxstate, sizeof(myContext.ext));
    {$endif}
    end;




    result:=newkernelhandler.SetThreadContext(hThread, myContext);
    //newkernelhandler.ResumeThread(myThread);
    //CloseHandle(myThread);
  end else
    result:=newkernelhandler.SetThreadContext(hthread, lpContext);

end;

function TKernelDebugInterface.GetThreadContext(hThread: THandle; var lpContext: TContext; isFrozenThread: Boolean=false):  BOOL;
var myThread : HANDLE;
begin
  outputdebugstring('TKernelDebugInterface.GetThreadContext');
  if NeedsToContinue and isFrozenThread then
  begin
    //myThread := newkernelhandler.OpenThread(THREAD_SUSPEND_RESUME or THREAD_GET_CONTEXT or THREAD_SET_CONTEXT,true,GetThreadId(hThread));
    //newkernelhandler.SuspendThread(myThread);
    result:=newkernelhandler.GetThreadContext(hThread, lpContext);
     outputdebugstring('This is the frozen thread so use the internal method'+inttohex(lpContext.Rip,8));
    //执行内核上下文更新之前，先从系统API获取一下寄存器上下文
    currentdebuggerstate.threadid:=GetThreadId(hThread);
    currentdebuggerstate.eax:=lpContext.{$ifdef cpu64}Rax{$else}eax{$endif};
    currentdebuggerstate.ebx:=lpContext.{$ifdef cpu64}Rbx{$else}ebx{$endif};
    currentdebuggerstate.ecx:=lpContext.{$ifdef cpu64}Rcx{$else}ecx{$endif};
    currentdebuggerstate.edx:=lpContext.{$ifdef cpu64}Rdx{$else}edx{$endif};
    currentdebuggerstate.esi:=lpContext.{$ifdef cpu64}Rsi{$else}esi{$endif};
    currentdebuggerstate.edi:=lpContext.{$ifdef cpu64}Rdi{$else}edi{$endif};
    currentdebuggerstate.ebp:=lpContext.{$ifdef cpu64}Rbp{$else}ebp{$endif};
    currentdebuggerstate.esp:=lpContext.{$ifdef cpu64}Rsp{$else}esp{$endif};
    currentdebuggerstate.eip:=lpContext.{$ifdef cpu64}Rip{$else}eip{$endif};
    {$ifdef cpu64}
    currentdebuggerstate.r8:=lpContext.r8;
    currentdebuggerstate.r9:=lpContext.r9;
    currentdebuggerstate.r10:=lpContext.r10;
    currentdebuggerstate.r11:=lpContext.r11;
    currentdebuggerstate.r12:=lpContext.r12;
    currentdebuggerstate.r13:=lpContext.r13;
    currentdebuggerstate.r14:=lpContext.r14;
    currentdebuggerstate.r15:=lpContext.r15;
    {$endif}
    currentdebuggerstate.cs:=lpContext.SegCs;
    currentdebuggerstate.ss:=lpContext.SegSs;
    currentdebuggerstate.ds:=lpContext.SegDs;
    currentdebuggerstate.es:=lpContext.SegEs;
    currentdebuggerstate.fs:=lpContext.SegFs;
    currentdebuggerstate.gs:=lpContext.SegGs;
    currentdebuggerstate.eflags:=lpContext.EFlags;

    if not globalDebug then
    begin
      currentdebuggerstate.dr0:=lpContext.Dr0;
      currentdebuggerstate.dr1:=lpContext.Dr1;
      currentdebuggerstate.dr2:=lpContext.Dr2;
      currentdebuggerstate.dr3:=lpContext.Dr3;
      currentdebuggerstate.dr6:=lpContext.Dr6;
      currentdebuggerstate.dr7:=lpContext.Dr7;
    end;

    {$ifdef cpu64}

    CopyMemory(@currentdebuggerstate.fxstate, @lpContext.FltSave, 512);
    {$else}
    CopyMemory(@currentdebuggerstate.fxstate, @lpContext.ext, sizeof(lpContext.ext));
    {$endif}
    if DBKDebug_GetDebuggerState(@currentdebuggerstate) then
    begin
         //use the currentdebuggerstate
      lpContext.{$ifdef cpu64}Rax{$else}eax{$endif}:=currentdebuggerstate.eax;
      lpContext.{$ifdef cpu64}Rbx{$else}ebx{$endif}:=currentdebuggerstate.ebx;
      lpContext.{$ifdef cpu64}Rcx{$else}ecx{$endif}:=currentdebuggerstate.ecx;
      lpContext.{$ifdef cpu64}Rdx{$else}edx{$endif}:=currentdebuggerstate.edx;
      lpContext.{$ifdef cpu64}Rsi{$else}esi{$endif}:=currentdebuggerstate.esi;
      lpContext.{$ifdef cpu64}Rdi{$else}edi{$endif}:=currentdebuggerstate.edi;
      lpContext.{$ifdef cpu64}Rbp{$else}ebp{$endif}:=currentdebuggerstate.ebp;
      lpContext.{$ifdef cpu64}Rsp{$else}esp{$endif}:=currentdebuggerstate.esp;
      lpContext.{$ifdef cpu64}Rip{$else}eip{$endif}:=currentdebuggerstate.eip;
      {$ifdef cpu64}
      lpContext.r8:=currentdebuggerstate.r8;
      lpContext.r9:=currentdebuggerstate.r9;
      lpContext.r10:=currentdebuggerstate.r10;
      lpContext.r11:=currentdebuggerstate.r11;
      lpContext.r12:=currentdebuggerstate.r12;
      lpContext.r13:=currentdebuggerstate.r13;
      lpContext.r14:=currentdebuggerstate.r14;
      lpContext.r15:=currentdebuggerstate.r15;
      {$endif}
      lpContext.SegCs:=currentdebuggerstate.cs;
      lpContext.SegSs:=currentdebuggerstate.ss;
      lpContext.SegDs:=currentdebuggerstate.ds;
      lpContext.SegEs:=currentdebuggerstate.es;
      lpContext.SegFs:=currentdebuggerstate.fs;
      lpContext.SegGs:=currentdebuggerstate.gs;
      lpContext.EFlags:=currentdebuggerstate.eflags;
      lpContext.Dr0:=currentdebuggerstate.dr0;
      lpContext.Dr1:=currentdebuggerstate.dr1;
      lpContext.Dr2:=currentdebuggerstate.dr2;
      lpContext.Dr3:=currentdebuggerstate.dr3;
      lpContext.Dr6:=currentdebuggerstate.dr6;
      lpContext.Dr7:=currentdebuggerstate.dr7;

      {$ifdef cpu64}
      CopyMemory(@lpContext.FltSave, @currentdebuggerstate.fxstate, 512);
      {$else}
      CopyMemory(@lpContext.ext, @currentdebuggerstate.fxstate, sizeof(lpContext.ext));
      {$endif}
    end;



    lpContext.ContextFlags:=0;
    //newkernelhandler.ResumeThread(myThread);
    //CloseHandle(myThread);
    if currentdebuggerstate.causedbydbvm<>0 then
      log('currentdebuggerstate.causedbydbvm<>0');
  end else
  begin
   // outputdebugstring('Use the default method');
    result:=newkernelhandler.GetThreadContext(hthread, lpContext);
  end;
end;

function TKernelDebugInterface.GetLastBranchRecords(lbr: pointer): integer;
type
  TQwordArray=array[0..0] of QWORD;
  PQwordArray=^TQWORDArray;
var l: PQWordarray;
    i: integer;
begin
  l:=PQWordarray(lbr);
  if NeedsToContinue then
  begin
    if lbr<>nil then //if nil then it's only a query of how many items there are
    begin
      for i:=0 to currentdebuggerstate.LBR_Count-1 do
        l[i]:=currentdebuggerstate.LBR[i];
    end;

    result:=currentdebuggerstate.LBR_Count-1;
  end
  else
    result:=-1;
end;

function TKernelDebugInterface.ContinueDebugEvent(dwProcessId: DWORD; dwThreadId: DWORD; dwContinueStatus: DWORD): BOOL;
var myThread : HANDLE;
    context :TCONTEXT;
    rflagMask: Cardinal;
begin
  outputdebugstring('TKernelDebugInterface.ContinueDebugEvent');
  if NeedsToContinue then
  begin
    myThread := newkernelhandler.OpenThread(THREAD_SUSPEND_RESUME or THREAD_GET_CONTEXT or THREAD_SET_CONTEXT,true,dwThreadId);
    if dwContinueStatus=DBG_EXCEPTION_NOT_HANDLED then//如果CE没有成功处理异常，就靠我们自己来处理
    begin

        context.ContextFlags :=  CONTEXT_FULL or CONTEXT_DEBUG_REGISTERS;
        newkernelhandler.GetThreadContext(myThread,context);
        currentdebuggerstate.eip:=0;
        DBKDebug_SetDebuggerState(@currentdebuggerstate);
        context.Rip:=currentdebuggerstate.eip; //将RIP重新路由到原始位置，并设置RF位=1
        rflagMask := 1 shl 16;
        context.EFlags := context.EFlags or rflagMask; //为了让事件继续模拟一个RF交给VT防止阻塞
        newkernelhandler.SetThreadContext(myThread,context);

    end;
    outputdebugstring('NeedsToContinue=true');
    DBKDebug_SetDebuggerState(@currentdebuggerstate);
    result:=DBKDebug_ContinueDebugEvent(dwContinueStatus=DBG_CONTINUE);
    NeedsToContinue:=false;
    newkernelhandler.ResumeThread(myThread);
    CloseHandle(myThread);
  end
  else
  begin
    outputdebugstring('NeedsToContinue=false');
    result:=true;
  end;
end;

function TKernelDebugInterface.WaitForDebugEvent(var lpDebugEvent: TDebugEvent; dwMilliseconds: DWORD): BOOL;
var injectedEvent: PInjectedEvent;
    myThread : HANDLE;
begin
  ZeroMemory(@lpDebugEvent, sizeof(TdebugEvent));

  if injectedEvents.Count>0 then
  begin
    result:=true;
    injectedEvent:=injectedEvents.Pop;
    if injectedEvent<>nil then //just to be sure
    begin
      lpDebugEvent.dwProcessId:=injectedevent.processid;
      lpDebugEvent.dwThreadId:=injectedevent.threadid;

      case injectedevent.eventType of
        etCreateProcess:
        begin
          lpDebugEvent.dwDebugEventCode:=CREATE_PROCESS_DEBUG_EVENT;
          lpDebugEvent.CreateProcessInfo.hProcess:=processhandle;
          lpDebugEvent.CreateProcessInfo.hThread:=OpenThread(THREAD_ALL_ACCESS,false, injectedevent.threadid);
        end;

        etCreateThread:
        begin
          lpDebugEvent.dwDebugEventCode:=CREATE_THREAD_DEBUG_EVENT;
          lpDebugEvent.CreateThread.hThread:=OpenThread(THREAD_ALL_ACCESS,false, injectedevent.threadid);
        end;
        etDestroyThread: lpDebugEvent.dwDebugEventCode:=EXIT_THREAD_DEBUG_EVENT;

      end;

      NeedsToContinue:=false; //it's not really paused
      freememandnil(injectedEvent);
    end;
  end
  else
  begin

    NeedsToContinue:=true;
    result:=DBKDebug_WaitForDebugEvent(dwMilliseconds);
    if result then
    begin
      OutputDebugString('Received a debug event that wasn''t injected');
      currentdebuggerstate.threadid := 0;
      currentdebuggerstate.eip := 0;
      //get the state and setup lpDebugEvent
      DBKDebug_GetDebuggerState(@currentdebuggerstate);

      Log(format('currentdebuggerstate.eip=%8x',[currentdebuggerstate.eip]));

      //this is only a bp hit event
      lpDebugEvent.dwDebugEventCode:=EXCEPTION_DEBUG_EVENT;

      lpDebugEvent.dwProcessId:=pid;
      lpDebugEvent.dwThreadId:=currentdebuggerstate.threadid;
      myThread := newkernelhandler.OpenThread(THREAD_SUSPEND_RESUME or THREAD_GET_CONTEXT or THREAD_SET_CONTEXT,true,lpDebugEvent.dwThreadId);
      newkernelhandler.SuspendThread(myThread);
      CloseHandle(myThread);
      lpDebugEvent.Exception.dwFirstChance:=1;
      lpDebugEvent.Exception.ExceptionRecord.ExceptionCode:=EXCEPTION_SINGLE_STEP;
      lpDebugEvent.Exception.ExceptionRecord.ExceptionAddress:=pointer(ptrUint(currentdebuggerstate.eip));
    end;
  end;
end;

function TKernelDebugInterface.EventCausedByDBVM: boolean;
begin
  result:=currentdebuggerstate.causedbydbvm<>0;
end;

function TKernelDebugInterface.canReportExactDebugRegisterTrigger: boolean;
begin
  result:=not globalDebug;
end;

destructor TKernelDebugInterface.destroy;
begin
  if injectedEvents<>nil then
    injectedEvents.free;

  if threadpoller<>nil then
    threadpoller.free;

  if pid<>0 then
    DBKDebug_StopDebugging;

  inherited destroy;
end;

constructor TKernelDebugInterface.create(globalDebug, canStepKernelcode: boolean);
begin
  inherited create;

  self.globalDebug:=globalDebug;

  LoadDBK32;

{$IFDEF CPU64}
  if loaddbvmifneeded=false then
    raise exception.create(rsKernelModeNeedsDBVM);
{$ENDIF}


  DBKDebug_SetAbilityToStepKernelCode(canStepKernelcode);
  DBKDebug_SetGlobalDebugState(globalDebug);
  injectedEvents:=TQueue.Create;

  fDebuggerCapabilities:=fDebuggerCapabilities+[dbcHardwareBreakpoint, dbcDBVMBreakpoint];
  name:='Kernelmode Debugger';

  fmaxSharedBreakpointCount:=4;
end;
{$endif}

end.

