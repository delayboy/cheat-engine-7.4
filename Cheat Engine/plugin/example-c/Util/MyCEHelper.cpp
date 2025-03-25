#include"MyCEHelper.h"


const char* hardwareHookScript = "[ENABLE]\n\
{$lua}\n\
registerSymbol('hookBkTo',0x%llx)\n\
{$asm}\n\
hookBkTo:\n\
jmp 0x%llx\n\
\n\
[DISABLE]\n\
{$lua}\n\
--deAlloc(getAddress('hookBkTo'));\n\
unregisterSymbol('hookBkTo');\n";

const char* fakeNtdllScript = "[ENABLE]\n\
{$lua}\n\
registerSymbol('fakeNtdll',0x%llx)\n\
{$asm}\n\
fakeNtdll:\n\
jmp fakeNtdll\n\
\n\
[DISABLE]\n\
{$lua}\n\
--deAlloc(getAddress('fakeNtdll'));\n\
unregisterSymbol('fakeNtdll');\n";

void luaUnRegisterLuaFunctionHighlight(const char* function_name)
{

	__luaFuncHandler("unregisterLuaFunctionHighlight", ("string"), 1, 0, function_name);
}
void luaRegisterLuaFunctionHighlight(const char* function_name)
{

	__luaFuncHandler("registerLuaFunctionHighlight", ("string"), 1, 0, function_name);
}

void luaSetComment(__int64 address, const char* comment)
{

	__luaFuncHandler("setComment", ("int", "string"), 2, 0, address, comment);
}
int luaGetCurrentDebuggerInterface()
{
	//DebugOptional
	//__luaFuncHandler("debug_getCurrentDebuggerInterface", ("int"), 0, 1);
	const char* testKey[4] = { "Use Windows Debugger","Use VEH Debugger","Use Kernel Debugger","Use DBVM Debugger" };
	PVOID settings = luaGetSettings(NULL);
	
	for (int i = 0; i < 4; i++) {
		const char* rValue = luaGetSettings_Value(settings, testKey[i]);
		if (strcmp(rValue, "1") == 0) {
			return (i + 1);
		}
	}
	
	return 0;
}

void luaSetBrkPoint(UINT_PTR address, int size, int trigger, int method)
{
	__luaFuncHandler("debug_setBreakpoint", ("long", "int", "int", "int"), 4, 0, address, size, trigger, method);

}
void luaLoadTable(const char* fileName, bool merge)
{
	__luaFuncHandler("loadTable", ("string", "boolean"), 2, 0, fileName, merge);
}
__int64 luaGetAddress(const char* symbol)
{
	__luaFuncHandler("getAddress", ("string", "int"), 1, 1, symbol);
	return funcHandlerRetValue;
}

void luaOpenProcess(int pid)
{
	__luaFuncHandler("openProcess", ("int"), 1, 0, pid);
}

PVOID luaGetSubPascalObj(PVOID userdate, const char* paramName)
{
	const char* argTypes[3] = { "pointer","string","pointer" };
	return (PVOID)luaFuncHandler("getProperty", argTypes, 2, 1, userdate, paramName);
}

//lua子函数调用，pascal模式
__int64 luaRunSubPascalFunc(PVOID userdate, const char* funcName, const char* argTypes[], int nArg, int rNum, ...)
{
	__luaFuncHandler("getMethodProperty", ("pointer", "string", "luaFuncTmpRet"), 2, 1, userdate, funcName);
	va_list vl;
	va_start(vl, rNum);
	__int64 r = v_luaFuncHandler_v("luaFuncTmpRet", argTypes, nArg, rNum, vl);
	va_end(vl);
	return r;
}
PVOID luaCreateForm(bool show)
{
	const char* argTypes[2] = { "boolean","TCustomForm" };
	return (PVOID)luaFuncHandler("createForm", argTypes, 1, 1, show);

}

PVOID luaGetSettings(const char* keyPath)
{
	const char* argTypes[2] = { "string","TLuaSettings"};
	return (PVOID)luaFuncHandler("getSettings", argTypes, 1, 1, keyPath);

}
const char* luaGetSettings_Value(PVOID setting_p, const char* keyNeedFind) {
	const char* argTypes[2] = {"string","string"};
	__int64 ret = luaGetTableSubMember(setting_p, "TLuaSettings", 2, "string", "Value", keyNeedFind);

	return (char*)ret;
}
void luaSetSettings_Value(PVOID setting_p, const char* keyNeedFind,const char* value) {
	luaSetTableSubMember(setting_p, "TLuaSettings", "Value", 1, "string", keyNeedFind, value);

}

void luaCloseForm(PVOID form)
{
	const char* argTypes[2] = { "TCustomForm" };

	luaRunTableSubFunc(form, "TCustomForm", "close", argTypes, 0, 0);

}
void luaShowForm(PVOID form)
{
	const char* argTypes[2] = { "TCustomForm" };
	luaRunTableSubFunc(form, "TCustomForm", "hide", argTypes, 0, 0);
	luaRunTableSubFunc(form, "TCustomForm", "show", argTypes, 0, 0);

}
PVOID luaCreateTreeView(PVOID form)
{
	const char* argTypes[2] = { "pointer","TCustomTreeView" };
	return (PVOID)luaFuncHandler("createTreeView", argTypes, 1, 1, form);

}
void luaLoadString(const char* script)
{
	lua_State* L = Exported.GetLuaState();
	luaL_loadstring(L, script);
	lua_call(L, 0, 0);
}
const char* luaLoadScriptWithReturn(const char* script)
{
	
	lua_State* L = Exported.GetLuaState();
	// 1. 加载 Lua 脚本
	if (luaL_loadstring(L, script) != LUA_OK) {
		const char* errorMessage = lua_tostring(L, -1);
		// 如果加载失败，输出错误信息
		std::cerr << "Error loading Lua script: " << lua_tostring(L, -1) << std::endl;
		lua_pop(L, 1); // 移除错误消息
		return errorMessage;
	}

	// 2. 执行 Lua 脚本，捕获错误
	if (lua_pcall(L, 0, 1,0) != LUA_OK) {
		// 如果执行失败，获取 Lua 栈上的错误消息
		const char* errorMessage = lua_tostring(L, -1);
		std::cerr << "Error running Lua script: " << errorMessage << std::endl;
		lua_pop(L, 1); // 移除错误消息
		return errorMessage;
	}
	else {
		std::cout << "Lua script ran successfully." << std::endl;
		return  lua_tostring(L, -1);
	}
	
}
PVOID luaGetTraceFile()
{
	luaLoadString("\
		for i = 0, getFormCount() - 1 do\n \
			local frm = getForm(i)\n \
			if frm.ClassName == \'TfrmTracer\' then\n \
				local CEtree = frm;\n \
				for i = 0, CEtree.ComponentCount - 1 do\n \
					if CEtree.Component[i].Name == \'lvTracer\' then\n \
						CETraceFile = CEtree.Component[i];\n \
					break;\n \
					end\n \
				end\n \
				break;\n \
			end\n \
		end\n ");
	return luaGetUserData("CETraceFile");
}
void luaSetUserData(PVOID objPointer, const char* name)
{
	lua_State* L = Exported.GetLuaState();
	lua_pushlightuserdata(L, objPointer);
	lua_setglobal(L, name);
}
PVOID luaGetUserData(const char* name)
{
	lua_State* L = Exported.GetLuaState();
	lua_getglobal(L, name);
	int type = lua_type(L, -1);
	if (type == LUA_TNIL) return NULL;
	__int64* addressOfObjectPointer = (__int64*)lua_touserdata(L, -1);
	PVOID objPointer = (PVOID)*addressOfObjectPointer;
	lua_pop(L, 1);
	return objPointer;
}

void luaPrint(const char* str)
{
	const char* argTypes[1] = { "string" };
	luaFuncHandler("print", argTypes, 1, 0, str);
}
void luaPrintf(char const* const str, ...)
{
	va_list vl;
	va_start(vl, str);//从str开始算参数
	char x[200];
	vsprintf_s(x, 200, str, vl);
	va_end(vl);
	luaPrint(x);
}

//lua函数调用中央处理器，省略号入参版
__int64 luaFuncHandler(const char* funcName, LPCSTR* argTypes, int nArg, int rNum, ...)
{
	va_list vl;
	va_start(vl, rNum);//从str开始算参数
	__int64 r = v_luaFuncHandler_v(funcName, argTypes, nArg, rNum, vl);
	va_end(vl);
	return r;

}
void luaPushArgs(lua_State* L, LPCSTR* argTypes, int nArg, int rNum, va_list ap)
{
	// 压入参数
	for (int i = 0; i < nArg; i++)
	{
		const char* type = argTypes[i];
		if (strcmpi(type, "char") == 0 || strcmpi(type, "boolean") == 0)
		{
			char arg = va_arg(ap, char);
			lua_pushboolean(L, arg);
		}
		else if (strcmpi(type, "string") == 0)
		{
			const char* arg = va_arg(ap, const char*);
			if (arg == NULL) lua_pushnil(L);
			else lua_pushstring(L, arg);
		}
		else if (strcmpi(type, "int") == 0 || strcmpi(type, "long") == 0)
		{
			lua_Integer arg = va_arg(ap, lua_Integer);
			lua_pushinteger(L, arg);
		}
		else if (strcmpi(type, "pointer") == 0 || strcmpi(type, "userdata") == 0)
		{
			PVOID arg = va_arg(ap, PVOID);
			if(arg == NULL) lua_pushnil(L);
			else lua_pushlightuserdata(L, arg);
		}
		else if (strcmpi(type, "UserMetaTable") == 0)
		{
			//使用全userdata数据
			//初始化全fulluserdata内存后，再配置metatable的方案。
			PVOID* temp = (PVOID*)lua_newuserdata(L, sizeof(PVOID*));
			*temp = va_arg(ap, PVOID);
			lua_getglobal(L, type);
			lua_setmetatable(L, -2);
		}
		else
		{
			//使用全userdata数据
			//这是获取全局userdata变量后，改写lightuser指针，形成的假fulluserdata方案。
			lua_getglobal(L, type);
			PVOID* temp = (PVOID*)lua_touserdata(L, -1);
			*temp = va_arg(ap, PVOID);
		}

	}
}
__int64 luaReturnValue(lua_State* L, const char* type)
{
	__int64 r = -1;
	if (strcmpi(type, "char") == 0 || strcmpi(type, "boolean") == 0)
	{
		r = lua_toboolean(L, -1);
	}
	else if (strcmpi(type, "string") == 0)
	{

		r = (__int64)lua_tostring(L, -1);
	}
	else if (strcmpi(type, "int") == 0 || strcmpi(type, "long") == 0)
	{
		r = lua_tointeger(L, -1);
	}
	else if (strcmpi(type, "pointer") == 0 || strcmpi(type, "userdata") == 0)
	{

		__int64* addressOfObjectPointer = (__int64*)lua_touserdata(L, -1);
		PVOID objPointer = (PVOID)*addressOfObjectPointer;
		r = (__int64)objPointer;
	}
	else
	{
		//使用全userdata数据
		__int64* addressOfObjectPointer = (__int64*)lua_touserdata(L, -1);
		PVOID objPointer = (PVOID)*addressOfObjectPointer;
		r = (__int64)objPointer;
		lua_setglobal(L, type);
		lua_getglobal(L, type);


	}
	lua_pop(L, 1);
	return r;
}

//lua函数调用中央处理器，虚拟入参版
__int64 v_luaFuncHandler_v(const char* funcName, LPCSTR* argTypes, int nArg, int rNum, va_list ap)
{
	lua_State* L = Exported.GetLuaState();
	lua_getglobal(L, funcName);
	luaPushArgs(L, argTypes, nArg, rNum, ap);
	lua_call(L, nArg, rNum, 0);  //告诉我们的L虚拟机，传入了1个参数，需要返回0个值；这个时候，lua主程序已经把栈内的两个参数取出，然后传入到函数myadd中，再然后执行这个函数，最后把计算的结果返回到栈顶。执行玩这个lua_call之后，栈内只剩下myadd的返回值了
	__int64 r = -1;
	if (rNum > 0) r = luaReturnValue(L, argTypes[nArg]);
	return r;

}
__int64 luaGetTableSubMember(PVOID userdata, const char* type , int subLevel, LPCSTR returnType, ...)
{
	lua_State* L = Exported.GetLuaState();
	//lua_getglobal(L, globalType);//可以使用lua_pushstring("subfunc")调用子函数
	//使用全userdata数据
	lua_getglobal(L, type);
	PVOID* temp = (PVOID*)lua_touserdata(L, -1);
	*temp = userdata;
	va_list vl;
	va_start(vl, returnType);//从str开始算参数
	for (int i = 0; i < subLevel; i++) {
		const char* arg = va_arg(vl, const char*);
		lua_pushstring(L, arg);
		lua_gettable(L, -2);
	}
	
	va_end(vl);
	__int64 r = -1;
	r = luaReturnValue(L, returnType);
	return r;
}

void luaSetTableSubMember(PVOID userdata, const char* type, const char* memberName,int subLevel,  const char* valueType,...)
{
	lua_State* L = Exported.GetLuaState();
	//lua_getglobal(L, globalType);//可以使用lua_pushstring("subfunc")调用子函数
	//使用全userdata数据
	lua_getglobal(L, type);
	PVOID* temp = (PVOID*)lua_touserdata(L, -1);
	*temp = userdata;
	lua_pushstring(L, memberName);
	__setConstChar({ valueType });
	va_list vl;
	va_start(vl, valueType);//从str开始算参数
	for (int i = 0; i < subLevel; i++) {
		const char* arg = va_arg(vl, const char*);
		lua_gettable(L, -2);
		lua_pushstring(L, arg);
		
	}


	luaPushArgs(L, argTypesTemp, 1, 0, vl);
	va_end(vl);
	lua_settable(L, -3);
}

//lua子函数调用，table模式
__int64 luaRunTableSubFunc(PVOID userdata, const char* type, const char* funcName, LPCSTR* argTypes, int nArg, int rNum, ...)
{
	lua_State* L = Exported.GetLuaState();
	//lua_getglobal(L, globalType);//可以使用lua_pushstring("subfunc")调用子函数
	//使用全userdata数据
	lua_getglobal(L, type);
	PVOID* temp = (PVOID*)lua_touserdata(L, -1);
	*temp = userdata;
	//lua_getglobal(L, globalName);
	lua_pushstring(L, funcName);
	lua_gettable(L, -2);
	//lua_pushvalue(L, -2);
	va_list vl;
	va_start(vl, rNum);//从str开始算参数
	luaPushArgs(L, argTypes, nArg, rNum, vl);

	va_end(vl);
	//TraverseLuaStack(L);
	// 此处要特别注意，需要多传一个self，参数个数要+1
	lua_pcall(L, nArg, rNum, 0);
	__int64 r = -1;
	if (rNum > 0) r = luaReturnValue(L, argTypes[nArg]);
	return r;

}

void luaTraverseStack(lua_State* L)
{
	int i;
	int top = lua_gettop(L);
	for (i = 1; i <= top; i++)
	{
		int t = lua_type(L, i);
		switch (t)
		{
		case LUA_TBOOLEAN:
		{
			luaPrintf("%s", lua_toboolean(L, i) ? "true" : "false");
		}break;
		case LUA_TSTRING:
		{
			luaPrintf("\'%s\'", lua_tostring(L, i));
		}break;
		case LUA_TNUMBER:
		{
			luaPrintf("%g", lua_tonumber(L, i));
		}break;
		case LUA_TNIL:
		{
			luaPrintf("nil");
		}break;
		default:
		{
			luaPrintf("other type:%d", t);
		}break;
		}
		luaPrintf(" ");
	}
	luaPrintf("\n");
}

TTreeNode* luaTreeNodeAdd(TTreeNode* nodes, const char* content)
{
	__setConstChar("string", "TreeNode");
	TTreeNode* newNode = (TTreeNode*)luaRunTableSubFunc(nodes, "TreeNode", "add", argTypesTemp, 1, 1, content);
	return newNode;
}

TTreeNode* luaTreeNodesAdd(TTreeNodes* nodes, const char* content)
{
	__setConstChar("string", "TreeNode");
	TTreeNode* newNode = (TTreeNode*)luaRunTableSubFunc(nodes, "TreeNodes", "add", argTypesTemp, 1, 1, content);
	return newNode;
}
TTreeNode* luaTreeNodesGetItem(TTreeNodes* treeNodes, int index)
{
	__setConstChar( "int","TreeNode");
	return 	(TTreeNode*)luaRunTableSubFunc(treeNodes, "TreeNodes", "getItem",argTypesTemp,1,1, index);
}
TTreeNodes* luaTreeViewItems(TCustomTreeView* treeView)
{
	return 	(TTreeNodes*)luaGetTableSubMember(treeView, "TCustomTreeView", 1, "TreeNodes", "Items");
}


char* luaInputQuery(const char* caption, const char* tips, char* defaultStr)
{
	__luaFuncHandler("inputQuery", ("string", "string", "string", "string"), 3, 1, caption, tips, defaultStr);
	return (char*)funcHandlerRetValue;
}

__int64 luaGetPreviousOpcode(__int64 address)
{
	__luaFuncHandler("getPreviousOpcode", ("int", "int"), 1, 1, address);
	return funcHandlerRetValue;
}
PVOID luaGetAddressList()
{
	__luaFuncHandler("getAddressList", ("AddressList"), 0, 1);
	return (PVOID)funcHandlerRetValue;
}
PVOID luaAddresslist_createMemoryRecord(PVOID addressList)
{
	__luaFuncHandler("addresslist_createMemoryRecord", ("AddressList", "MemoryRecord"), 1, 1, addressList);
	return (PVOID)funcHandlerRetValue;
}
void luaRecordSetActive(PVOID record, bool active)
{
	__setConstChar("boolean");
	luaRunTableSubFunc(record, "MemoryRecord", "setActive", argTypesTemp, 1, 0, active);
}
PVOID addScriptToTable(char* title, char* script,PVOID parent_record)
{
	
	PVOID record = luaAddresslist_createMemoryRecord(luaGetAddressList());

	Exported.memrec_setType(record, vtAutoAssembler);
	Exported.memrec_setDescription(record, title);
	Exported.memrec_setScript(record, script);
	if (parent_record) {
		Exported.memrec_setType(parent_record, vtCustom);
		Exported.memrec_setDescription(parent_record, "MyManyLuaScript");
		Exported.memrec_appendtoentry(record, parent_record);
		luaSetTableSubMember(parent_record, "MemoryRecord", "IsAddressGroupHeader", 0,"boolean", false);
		luaSetTableSubMember(parent_record, "MemoryRecord", "IsGroupHeader", 0,"boolean", true);


		luaSetTableSubMember(parent_record, "MemoryRecord", "Options", 0, "string", "[moHideChildren,moAllowManualCollapseAndExpand,moManualExpandCollapse]");
		luaSetTableSubMember(parent_record, "MemoryRecord", "Collapsed", 0,"boolean", true);
	}
	return record;
}
PVOID luaCreateMemoryRecord() {
	
	return luaAddresslist_createMemoryRecord(luaGetAddressList());
}

__int64 luaAllocateMemory(int size, __int64 baseAddr, bool protect)
{
	__luaFuncHandler("allocateMemory", ("int", "int", "boolean", "int"), 3, 1, size, baseAddr, protect);
	return funcHandlerRetValue;
}

bool luaDeAlloc(__int64 addr)
{
	__luaFuncHandler("deAlloc", ("int", "int"), 1, 1, addr);
	return (bool)funcHandlerRetValue;
}




