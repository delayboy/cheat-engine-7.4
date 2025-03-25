#include "MyCeMiniUi.h"
PVOID mainForm = NULL;
PVOID textEdit = NULL;
TCustomTreeView* mainTreeView = NULL;
HANDLE eventSignal = NULL;
char ret_str[2048];
std::string stackToStr(std::vector<int> stack) {
	std::string ret = "[";
	for (int i = 0; i < stack.size(); i++) {
		ret = ret.append(std::to_string(i)).append(",");
	}
	if (stack.size() > 0) ret.pop_back();
	ret = ret.append("]");
	return ret;

}

void enumAllTTreeNode(TTreeNode* node) {
	std::vector<int> stack;
	stack.push_back(-1);
	FILE* fp = generateFileStream("C:/traceOutput.txt");
	while (stack.size() > 0)
	{
		int peek_index = stack[stack.size() - 1] + 1;
		stack.pop_back();
		if (peek_index == 0 && node->Data && node->ftext) {
			std::string content = std::to_string(node->Count).append(stackToStr(stack));

			if (fp) fprintf(fp, "%s\t-\t0x%llx\t-\t%s\n", node->ftext, node->Data->c.Rip, content.c_str());
			content = content.append(node->ftext);
			luaTreeNodesAdd(mainTreeView->Items, content.c_str());
		}
		if (peek_index < node->Count) {
			stack.push_back(peek_index);
			stack.push_back(-1);
			node = node->Items[peek_index];

		}
		else {
			node = node->parent;
		}
	}
	if (fp)fclose(fp);
}
void __stdcall showClickButton()
{
	PVOID userData = luaGetTraceFile();
	if (userData == NULL) {
		luaCloseForm(mainForm);
		return;
	}
	TCustomTreeView* treeView = (TCustomTreeView*)userData;

	TTreeNodes* treeNode = treeView->Items;

	for (int i = 0; i < treeNode->FTopLvlCount; i++)
	{

		TTreeNode* node = treeNode->Item[i];
		//luaPrintf("TTreeNode.Data:0x%llx", (__int64)node->Data);
		enumAllTTreeNode(node);


		//luaPrintf("TTreeNode.Data.iN:%s", node->data->instruction);
		//luaLoadString("print(string.format('CETraceFile.Data = %s',CETraceFile.Items.Item[0].Data))");

	}
}
void __stdcall mainMenuOnClose()
{
	Exported.control_getCaption(textEdit, ret_str, 2048);
	mainForm = NULL;
	mainTreeView = NULL;
	textEdit = NULL;
	SetEvent(eventSignal);
	

}
void waitForFormClose() {
	if (eventSignal) {
		ResetEvent(eventSignal);
		bool is_waiting = true;
		MSG msg;
		while (is_waiting) {
			WORD result = MsgWaitForMultipleObjects(1, &eventSignal, FALSE, INFINITE, QS_ALLINPUT);//这个方法可以同时等待消息和信号，避免频繁轮询，提高性能
			if (result == WAIT_OBJECT_0) {
				is_waiting = false;
			}
			else if (result == WAIT_OBJECT_0 + 1) {
				while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
					TranslateMessage(&msg);
					DispatchMessage(&msg);
				}
			}
		}

	}
}

const char* InitMyCeMiniUi(const char* ini_text,bool wait_close)
{
	if (mainForm) {
		luaShowForm(mainForm);
		char* new_text = getDynamicChars(ini_text);
		Exported.control_setCaption(textEdit, new_text); //	Exported.ShowMessage("Called from lua");
		free(new_text);
		if(wait_close)waitForFormClose();
		return ret_str;
	}
	if (eventSignal == NULL) {
		eventSignal = CreateEventA(NULL, TRUE, FALSE, NULL);

	}
	//创建插件主窗口
	mainForm = luaCreateForm(true);
	Exported.form_onClose(mainForm, mainMenuOnClose);
	Exported.form_centerScreen(mainForm);
	Exported.control_setSize(mainForm, 800, 600);
	mainTreeView = (TCustomTreeView*)luaCreateTreeView(mainForm);
	TTreeNodes* item = luaTreeViewItems(mainTreeView);
	//luaPrintf("real TTreeNodes: 0x%llx  mainTreeView.Items: 0x%llx , open: 0x%llx", (__int64)item, (__int64)mainTreeView->Items, (__int64)mainTreeView->OpenSourceUnkown);

	TTreeNode* node = luaTreeNodesAdd(mainTreeView->Items, "test");
	node = luaTreeNodesGetItem(mainTreeView->Items, 0);
	Exported.control_setAlign(mainTreeView, Right);
	Exported.control_setSize(mainTreeView, 700, 300);

	/*luaPrintf("real item[0] = 0x%llx ", (__int64)node);
	luaPrintf("treeNodes = 0x%llx ", (__int64)mainTreeView->Items);
	luaPrintf("item[0] = 0x%llx ", (__int64)mainTreeView->Items->Item[0]);
	luaLoadString("print(string.format('TreeNode.Data = %s',TreeNode.Data))");
	luaPrintf("item[0].data = 0x%llx ", (__int64)mainTreeView->Items->Item[0]->Data);*/

	textEdit = Exported.createMemo(mainForm);
	Exported.control_setSize(textEdit, 300, 300);
	Exported.control_setAlign(textEdit, Top);
	Exported.control_setCaption(mainForm, "my plugin ui");

	PVOID label = Exported.createLabel(mainForm);
	Exported.control_setAlign(label, Left);
	Exported.control_setCaption(label, "my main");
	PVOID button = Exported.createButton(mainForm);

	Exported.control_setAlign(button, Bottom);
	Exported.control_onClick(button, showClickButton);
	Exported.control_setCaption(button, "clk");

	char* new_text = getDynamicChars(ini_text);
	Exported.control_setCaption(textEdit, new_text); //	Exported.ShowMessage("Called from lua");
	free(new_text);
	if (wait_close)waitForFormClose();
	return ret_str;
}

void __stdcall mainmenuplugin(void) {

	int r = MessageBoxA(NULL, "[Yes] to load CE driver or [No] to load console", "WARNING", MB_YESNOCANCEL);
	if(r == IDYES) Exported.loadDBK32(); //IDOK
	else if(r == IDNO) {
		const HWND consoleWindow = GetConsoleWindow();
		if (consoleWindow == NULL) InitConsoleWindow(true);
		else InitConsoleWindow(false);
	}
}

int lua_plugin_print(lua_State* L) //make sure this is cdecl
{
	int type = lua_type(L, -1);
	const char* text;
	if (type == LUA_TSTRING) {//nil
		text = lua_tostring(L, -1);
		
	}
	else {
		text = lua_tostring(L, -2);
	}
	

	
	
	
	if (type == LUA_TSTRING) {
		InitMyCeMiniUi(text, false);
		lua_pushstring(L, "");
	}
	else {
		InitMyCeMiniUi(text,true);
		lua_pushstring(L, ret_str);
	}
	

	return 1;
}