#include"MyCEHelper.h"
#include"StringHelper.h"
#include "FileHelper.h"

std::string getBaseName(LPCSTR filePath)
{
	char* path = (char*)malloc(strlen(filePath));
	if (path)
	{
		strcpy(path, filePath);
		char* p = path + strlen(path) - 1;

		while (p != path)
		{
			if (*p == '\\' || *p == '/')
			{
				p++; //向前加一位,去掉斜杠

				return std::string(p);
			}
			p--;
		}
	}

	return "";
}
std::string getFileTail(LPCSTR filePath)
{
	std::string path = std::string(filePath);
	int pe = path.find_last_of(".");
	std::string tail = path.substr(pe);
	return  tail;
}

char* getDynamicChars(std::string str)
{
	char* newBytes = (char*)malloc((str.length() + 1) * sizeof(char));
	if (newBytes) memcpy(newBytes, str.c_str(), str.length() + 1);
	return newBytes;
}
LPCSTR chooseFile()
{
	//打开文件管理窗口
	TCHAR szBuffer[MAX_PATH] = { 0 };
	OPENFILENAME file = { 0 };
	file.hwndOwner = NULL;
	file.lStructSize = sizeof(file);
	file.lpstrFilter = TEXT("Excel文件(*.xlsx,*.xls)\0*.xlsx;*.xls;*.exe\0Txt文件(*.txt)\0*.txt\0");//要选择的文件后缀
	file.lpstrInitialDir = TEXT("C:\\");//默认的文件路径 
	file.lpstrFile = szBuffer;//存放文件的缓冲区
	file.nMaxFile = sizeof(szBuffer) / sizeof(*szBuffer);
	file.nFilterIndex = 0;
	file.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER;//标志如果是多选要加上OFN_ALLOWMULTISELECT
	BOOL bSel = GetOpenFileName(&file);
	luaPrintf("The User Choose File:%s", file.lpstrFile);
	return file.lpstrFile;

}

std::string getLnkFormPath(std::string filePath)
{
	// 初始化
	TCHAR wRet[MAX_PATH];
	std::wstring lnkPath = s2ws(filePath);
	// 初始化 COM 库
	HRESULT result = CoInitialize(NULL);
	IPersistFile* pPF = NULL;

	// 创建 COM 对象
	HRESULT hr = CoCreateInstance(
		CLSID_ShellLink,			// CLSID
		NULL,						// IUnknown 接口指针
		CLSCTX_INPROC_SERVER,		// CLSCTX_INPROC_SERVER：以 Dll 的方式操作类对象 
		IID_IPersistFile,			// COM 对象接口标识符
		(void**)(&pPF)				// 接收 COM 对象的指针
	); if (FAILED(hr)) { luaPrint("CoCreateInstance failed."); }

	// 判断是否支持接口
	IShellLink* pSL = NULL;
	hr = pPF->QueryInterface(
		IID_IShellLink,				// 接口 IID
		(void**)(&pSL)				// 接收指向这个接口函数虚标的指针
	); if (FAILED(hr)) { luaPrint("QueryInterface failed."); }

	// 打开文件
	hr = pPF->Load(
		lnkPath.c_str(),					// 文件全路径
		STGM_READ					// 访问模式：只读
	); if (FAILED(hr)) { luaPrintf("Load failed ：%d", GetLastError()); }

	// 获取 Shell 链接来源
	hr = pSL->GetPath(wRet, MAX_PATH, NULL, 0);

	// 关闭 COM 库
	pPF->Release();
	CoUninitialize();
	return std::string(wRet);



}


std::map<std::string, std::string> GetManyLuaScriptFromTxt()
{
	char path[255];
	char* nowPath = _getcwd(path, 255);

	if (nowPath != 0) nowPath = strcat(nowPath, "\\MyManyLuaScript.txt");
	//SetConsoleOutputCP(65001);//用于函数SetConsoleOutputCP(65001);更改cmd编码为utf8
	std::map<std::string, std::string>  ret;
	std::ifstream in(nowPath);
	std::string line;
	std::string script = "";
	std::string script_name = "Default";
	if (in) // 有该文件
	{
		while (getline(in, line)) // line中不包括每行的换行符
		{
			std::string target_str = "MyLuaScriptName:";
			size_t start_pos = line.find(target_str);
			if (start_pos != std::string::npos) {
				line.replace(start_pos, target_str.length(), "");
				ret[line] = script;
				script = "";

			}
			else {
				script = script.append(line).append("\n");
			}


		}
		luaPrintf(nowPath);
	}
	else // 没有该文件
	{
		luaPrintf("no such file: %s", nowPath);

	}
	return ret;
}

std::vector<std::pair<std::string, std::string>>  GetManyLuaScriptFromResource(HMODULE hModule) {

	std::vector<std::pair<std::string, std::string>> ret;
	std::string script = "";
	std::string script_name = "Default";
	//先判断我们指定的资源是否存在
	HRSRC hResInfo = FindResourceA(hModule, MAKEINTRESOURCE(101), "LuaScript");
	if (NULL == hResInfo)
	{
		luaPrintf("NULL == hResInfo");
		return ret;
	}

	//开始调入指定的资源到内存
	HGLOBAL hResData = LoadResource(hModule, hResInfo);
	if (!hResData) {
		luaPrintf("NULL == hResData");
		return ret;
	}
	LPVOID lpResData = LockResource(hResData);
	DWORD dwResSize = SizeofResource(hModule, hResInfo);

	if (lpResData) {
		//保存到文件
		DWORD dwWritten = 0;

		// 将资源数据复制到一个字符串
		std::string resourceData(static_cast<char*>(lpResData), dwResSize);


		// 将 UTF-8 字符串转换为 UTF-16
		int wideCharSize = MultiByteToWideChar(CP_UTF8, 0, resourceData.c_str(), -1, NULL, 0);
		std::vector<wchar_t> wideCharBuffer(wideCharSize);
		MultiByteToWideChar(CP_UTF8, 0, resourceData.c_str(), -1, wideCharBuffer.data(), wideCharSize);

		// 将 UTF-16 转换为 ANSI（如果需要在消息框中显示）
		int ansiCharSize = WideCharToMultiByte(CP_ACP, 0, wideCharBuffer.data(), -1, NULL, 0, NULL, NULL);
		std::vector<char> ansiCharBuffer(ansiCharSize);
		WideCharToMultiByte(CP_ACP, 0, wideCharBuffer.data(), -1, ansiCharBuffer.data(), ansiCharSize, NULL, NULL);


		// 使用istringstream将字符串按行读取
		std::istringstream stream(resourceData);
		// 使用istringstream将 ANSI 字符串按行读取
		//std::istringstream stream(ansiCharBuffer.data());
		std::string line;
		while (std::getline(stream, line)) {
			// 在这里处理每一行
			std::string target_str = "MyLuaScriptName:";
			size_t start_pos = line.find(target_str);
			if (start_pos != std::string::npos) {
				line.replace(start_pos, target_str.length(), "");
				ret.push_back(std::make_pair(line, script));
				script = "";

			}
			else {
				script = script.append(line).append("\n");
			}
		}
		luaPrintf("Load ManyScript Success");

	}
	else {
		luaPrintf("NULL == lpResData");


	}

	FreeResource(hResData);


	return ret;


}

FILE* generateFileStream(const char* path)
{
	FILE* fp;

	fp = fopen(path, "w");
	return fp;

}

bool fileExist(const char* path)
{
	if (FILE* file = fopen(path, "r")) {
		fclose(file);
		return true;
	}
	else {
		return false;
	}

}

char* get_cwd_file(char* nowPath, const char* file_name) {

	nowPath = _getcwd(nowPath, MAX_PATH);

	if (nowPath != 0) nowPath = strcat(nowPath, file_name);
	if (nowPath) luaPrintf(nowPath);
	return nowPath;
}