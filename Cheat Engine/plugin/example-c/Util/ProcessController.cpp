#include "ProcessController.h"
#include "FileHelper.h"
PVOID mapProcessMemory(HANDLE proccess, __int64 start_address,size_t nSize) {

	if (proccess == NULL)
		return (PVOID)start_address;
	char* buffer = (char*)malloc(nSize);
	if (buffer) {
		size_t read_len = 0;
		ReadProcessMemory(proccess, (LPCVOID)start_address, buffer, nSize, &read_len);
		return buffer;
	}
	else {
		assert(buffer == NULL);
		return NULL;
	}
	

}
//这里面类型强制转换很重要，否则加法运算后将不是直接的地址运算
__int64 ProCntrl::EnumModuleExportFunction(HANDLE proccess, HMODULE lib, const char* funcName, bool is32)
{
	char buffer[USN_PAGE_SIZE];
	

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)mapProcessMemory(proccess,(__int64)lib,sizeof(*pDos));
	assert(pDos->e_magic == IMAGE_DOS_SIGNATURE);
	//千万不要使用RvaToOffset，网上抄来的都是错的
	DWORD exportOffset;
	if (is32) {
		PIMAGE_NT_HEADERS32 header = (PIMAGE_NT_HEADERS32)mapProcessMemory(proccess, ((__int64)lib + pDos->e_lfanew), sizeof(*header));
		assert(header->Signature == IMAGE_NT_SIGNATURE);
		assert(header->OptionalHeader.NumberOfRvaAndSizes > 0);
		exportOffset = header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	}
	else {
		PIMAGE_NT_HEADERS64 header = (PIMAGE_NT_HEADERS64)mapProcessMemory(proccess, ((__int64)lib + pDos->e_lfanew), sizeof(*header));
		assert(header->Signature == IMAGE_NT_SIGNATURE);
		assert(header->OptionalHeader.NumberOfRvaAndSizes > 0);
		exportOffset = header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		free(header);
	}
	
	
	if (exportOffset < 1) {
		return NULL;
	}
	PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY) mapProcessMemory(proccess, ((__int64)lib + exportOffset), sizeof(*exports));
	char* moduleName = (char*)mapProcessMemory(proccess, (__int64)((byte*)lib + exports->Name), 255);
	FILE* fp = generateFileStream("C:/1.txt");
	fprintf(fp, "(f:%d,n:%d)(exportOffset:%x)%s\n", exports->NumberOfNames, exports->NumberOfFunctions, exportOffset,moduleName);
	assert(exports->AddressOfNames != 0);
	
	DWORD nameOffset = exports->AddressOfNames;
	DWORD* names = (DWORD*)mapProcessMemory(proccess, ((__int64)lib + nameOffset), sizeof(DWORD)*exports->NumberOfNames);
	DWORD funcAddrOffset = exports->AddressOfFunctions;
	DWORD* pFunc = (DWORD*)mapProcessMemory(proccess, (__int64)((byte*)lib + funcAddrOffset), sizeof(DWORD) * exports->NumberOfFunctions);
	// 获取该名称对应的函数序号(function索引)
	DWORD ordinalOffset = exports->AddressOfNameOrdinals;
	WORD* ordinalMap = (WORD*)mapProcessMemory(proccess, ((__int64)lib + ordinalOffset), sizeof(WORD) * exports->NumberOfNames);
	for (int i = 0; i < exports->NumberOfNames; i++)
	{
		int offset = names[i];
		char* fName = (char*)mapProcessMemory(proccess, ((__int64)lib + offset),255);
		int funcOffset = pFunc[ordinalMap[i]];
		fprintf(fp, "%s Rva@%x\n", fName, funcOffset);
		if (strcmpi(fName, funcName) == 0)
		{
			//luaPrintf("Export: %s\n", fName);

		
			free(fName);
			free(ordinalMap);
			free(pFunc);
			free(names);
			free(moduleName);
			free(exports);
			
			free(pDos);
			fclose(fp);
			return (__int64)lib + funcOffset;
		}
		free(fName);

	}
	free(ordinalMap);
	free(pFunc);
	free(names);
	free(moduleName);
	free(exports);
	free(pDos);
	fclose(fp);

	return NULL;

}
HMODULE ProCntrl::InnerGetModule2(HANDLE proccess, std::string basename)
{
	HMODULE hMods[1024];
	HANDLE pHandle = proccess;
	DWORD cbNeeded;
	unsigned int i;
	int each_flag[2] = { LIST_MODULES_32BIT ,LIST_MODULES_64BIT };
	for (int i = 0; i < 2; i++) {

	}
	bool runover = false;
	runover = EnumProcessModules(pHandle, hMods, sizeof(hMods), &cbNeeded);//EnumProcessModules
	if (runover)
	{
		for (i = 0; i <= (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];
			if (GetModuleFileNameExA(pHandle, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
			{
				std::string wstrModName = std::string(szModName);
				//you will need to change this to the name of the exe of the foreign process
				printf("module:%s\n", wstrModName.c_str());
				if (wstrModName.find(basename) != std::string::npos)
				{

					return hMods[i];
				}
			}
		}
	}

	return nullptr;
}

HMODULE ProCntrl::GetModule(HANDLE proccess, std::string basename)
{
	HMODULE hMods[1024];
	HANDLE pHandle = proccess;
	DWORD cbNeeded;
	unsigned int i;
	int each_flag[2] = { LIST_MODULES_32BIT ,LIST_MODULES_64BIT };
	for (int i = 0; i < 2; i++) {
		
	}
	bool runover = false;
	runover = EnumProcessModulesEx(pHandle, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_32BIT);//EnumProcessModules
	if (runover)
	{
		for (i = 0; i <= (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];
			if (GetModuleFileNameExA(pHandle, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
			{
				std::string wstrModName = std::string(szModName);
				//you will need to change this to the name of the exe of the foreign process
				printf("module:%s\n", wstrModName.c_str());
				if (wstrModName.find(basename) != std::string::npos)
				{

					return hMods[i];
				}
			}
		}
	}
	
	return InnerGetModule2(proccess, basename);
}



// Type = CREATE_SUSPENDED 新建进程的主线程挂起，调用ResumeThread(pis.hThread);激活新进程的主线程
BOOL ProCntrl::CreateChildProcess(const LPCSTR lpszExecFile, PROCESS_INFORMATION& proinfo, DWORD TYPE)
{
	STARTUPINFO si = { sizeof(si) };  //启动信息  
	PROCESS_INFORMATION pi;  //返回信息结构体  
	BOOL bStatus = CreateProcess(lpszExecFile, NULL, NULL, NULL, FALSE, TYPE, NULL, NULL, &si, &pi);//创建进程  
	if (!bStatus)
	{
		return FALSE;
	}
	proinfo = pi;
	return TRUE;
}

DWORD ProCntrl::RvaToOffset(DWORD dwRva, byte* buffer)// 计算偏移的函数，将RVA转化成偏移
{
	//解析Dos头
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	//PE头
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + buffer);
	//区段表
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	//判断是否落在了头部当中

	for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		//VirtualAddress 起始地址
		//Size 长度
		//VirtualAddress + Size 结束地址
		//判断是否落在某个区段内
		if (pSection[i].VirtualAddress <= dwRva && dwRva < pSection[i + 1].VirtualAddress)
		{
			return dwRva - pSection[i].VirtualAddress + pSection[i].PointerToRawData;
		}
		if (dwRva >= pSection[i].VirtualAddress && dwRva <= pSection[i].VirtualAddress + pSection[i].Misc.VirtualSize)
		{
			//dwRva - pSection[i].VirtualAddress是数据目录表起始地址到区段起始地址的偏移（OFFSET）
			//pSection[i].PointerToRawData  区段到文件头的偏移（OFFSET）
			//返回的是数据目录表起始地址到文件头的偏移（OFFSET）
			return dwRva - pSection[i].VirtualAddress + pSection[i].PointerToRawData;
		}
	}
	return 0;


}
__int64 ProCntrl::getOEP(byte* buffer)
{
	//Dos头,注意Dos结构体作为指针来直接加减会出很多问题！！！
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	//PE头
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + buffer);

	//是32位PE文件
	if (pNt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		PIMAGE_NT_HEADERS32 pNtReal = (PIMAGE_NT_HEADERS32)(pDos->e_lfanew + buffer);

		return (__int64)pNtReal->OptionalHeader.AddressOfEntryPoint;
	}
	else {
		PIMAGE_NT_HEADERS64 pNtReal = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);
		return  pNtReal->OptionalHeader.AddressOfEntryPoint;
	}
}
bool ProCntrl::is32PE(byte* buffer)
{
	//PE头
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + buffer);
	//定位数据目录表中的TLS表
	PIMAGE_DATA_DIRECTORY pTLSDir;
	//是32位PE文件
	if (pNt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		return true;
	}
	else return false;
}
__int64 ProCntrl::getTLSCallBackTable(byte* buffer)
{
	//Dos头
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	//PE头
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + buffer);
	//定位数据目录表中的TLS表
	PIMAGE_DATA_DIRECTORY pTLSDir;
	//是32位PE文件
	if (pNt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		PIMAGE_NT_HEADERS32 pNtReal = (PIMAGE_NT_HEADERS32)(pDos->e_lfanew + buffer);
		pTLSDir = (pNtReal->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_TLS);
		if (pTLSDir->VirtualAddress == 0x0) return 0;
		//填充TLS结构,通过计算RVA来对其进行填充
		PIMAGE_TLS_DIRECTORY32 pTLSReal = (PIMAGE_TLS_DIRECTORY32)(RvaToOffset(pTLSDir->VirtualAddress, (BYTE*)pDos) + buffer);
		return pTLSReal->AddressOfCallBacks;
	}
	else {
		PIMAGE_NT_HEADERS64 pNtReal = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);
		pTLSDir = (pNtReal->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_TLS);
		if (pTLSDir->VirtualAddress == 0x0) return 0;
		//填充TLS结构,通过计算RVA来对其进行填充
		PIMAGE_TLS_DIRECTORY64 pTLSReal = (PIMAGE_TLS_DIRECTORY64)(RvaToOffset(pTLSDir->VirtualAddress, (BYTE*)pDos) + buffer);
		return pTLSReal->AddressOfCallBacks;
	}
}
byte* ProCntrl::readPEFile(LPCSTR filePath)
{
	//文件读取
	FILE* pFile = NULL;
	byte* buffer;
	long nFileLength = 0;
	pFile = fopen(filePath, "rb");
	fseek(pFile, 0, SEEK_END);
	nFileLength = ftell(pFile);
	rewind(pFile);
	long imageLength = nFileLength * sizeof(byte) + 1;
	buffer = (byte*)malloc(imageLength);
	if (buffer)
	{
		memset(buffer, 0, imageLength);
		fread(buffer, 1, imageLength, pFile);
	}
	return buffer;
}