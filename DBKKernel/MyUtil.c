#include "MyUtil.h"
My_CriticalSection sendstringfCS = { .name = "sendstringfCS", .debuglevel = 1 };
My_CriticalSection sendstringCS = { .name = "sendstringCS", .debuglevel = 1 };
HANDLE LOG_SERIAL = NULL;
NTSTATUS innerInitLog(PCWSTR SourceString) {
	NTSTATUS status;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK iostatus;
	UNICODE_STRING pathname;
	RtlInitUnicodeString(&pathname, SourceString);
	InitializeObjectAttributes(&oa, &pathname, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwCreateFile(&LOG_SERIAL, GENERIC_WRITE | GENERIC_READ, &oa, &iostatus, NULL, 0, FILE_SHARE_WRITE | FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	return status;
}
BOOLEAN InitLog() {
	if (NT_SUCCESS(innerInitLog(L"\\Device\\Serial0"))) {
		return TRUE;
	}
	else if (NT_SUCCESS(innerInitLog(L"\\Device\\Serial1"))) {
		return TRUE;
	}
	else if (NT_SUCCESS(innerInitLog(L"\\Device\\Serial2"))) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}

void UnInitLog() {
	if (LOG_SERIAL) {
		ZwClose(LOG_SERIAL);
	}
}
int getAPICID(void)
{

	int cpuInfo[4] = { 0 };

	__cpuid(cpuInfo, 1);
	return (cpuInfo[1] >> 24) + 1;
}
void inner_csEnter(PMy_CriticalSection CS, int apicid)
{


	//get current apicid (from cpuid)

	if ((CS->locked) && (CS->apicid == apicid))
	{
		//already locked but the locker is this cpu, so allow, just increase lockcount
		CS->lockcount++;
		return;
	}

	asm_spinlock(&(CS->locked)); //sets CS->locked to 1

	//here so the lock is aquired and locked is 1
	CS->lockcount = 1;
	CS->apicid = apicid;

}

void inner_csLeave(PMy_CriticalSection CS, int apicid)
{
	//int apicid = getAPICID() + 1; //+1 so it never returns 0

	if ((CS->locked) && (CS->apicid == apicid)) // && (CS->apicid == apicid)
	{
		CS->lockcount--;
		if (CS->lockcount == 0)
		{
			//unlock
			CS->apicid = -1; //set to a invalid apicid
			CS->locked = 0;

		}
	}
}



void sendchar(char c)
{


#if (!defined SERIALPORT) || (SERIALPORT == 0)
	_Unreferenced_parameter_(c);
	return;
#else
	char x;
	if (c == '\r')
		return;

	x = inportb(SERIALPORT + 5);
	//while ((x & 0x20) != 0x20)
	while ((x & 0x40) != 0x40)
		x = inportb(SERIALPORT + 5);

	outportb(SERIALPORT, c);

	if (c == '\n')
	{
		x = inportb(SERIALPORT + 5);
		while ((x & 0x20) != 0x20)
			x = inportb(SERIALPORT + 5);

		outportb(SERIALPORT, '\r');
	}
#endif // SERIALPORT ==0

}

char inner_getchar(void)
{
	/* returns 0 when no char is pressed
		 use readstring to wait for keypresses */
#if (!defined SERIALPORT) || (SERIALPORT == 0)
	return 1;
#else
	if (inportb(SERIALPORT + 5) & 0x1)
		return inportb(SERIALPORT);
	else
		return 0;
#endif


}
char waitforchar(void)
{
#if (!defined SERIALPORT) || (SERIALPORT == 0)
	return 1;
#else
	char c = 0;
	while (c == 0)
		c = inner_getchar();

	return c;
#endif
}
void sendstring(char* s)
{
#if (!defined SERIALPORT) || (SERIALPORT == 0)
	_Unreferenced_parameter_(s);
	MyKdPrint(s);
	return;
#else
	int i;


	int apicid = getAPICID() + 1; //+1 so it never returns 0
	inner_csEnter(&sendstringCS, apicid);
	for (i = 0; s[i]; i++)
		sendchar(s[i]);
	inner_csLeave(&sendstringCS, apicid);
#endif


}





int readstring(char* s, int minlength, int maxlength)
{
	int i = 0;
	//keeps reading till it hits minlength, but can go over till maxlength (depending on the size of the uart buffer)
	while (i < minlength)
	{
		s[i] = waitforchar();
		if ((s[i] == 13) || (s[i] == 10))
		{
			s[i] = 0;
			return i;
		}
		sendchar(s[i]);

		if (s[i]) i++;
	}

	s[i] = 0;

	//minlength reached
	while ((i < maxlength) && (s[i]))
	{
		s[i] = inner_getchar();
		i++;
		if (s[i])
			sendchar(s[i]);
	}

	return i;
}

void sendstringf(char* string, ...)
{
#ifdef  _WIN32
	char x[1024];
	va_list vl;
	_crt_va_start(vl, string);//��str��ʼ�����
	vsprintf_s(x, 1024, string, vl);
	_crt_va_end(vl);
	sendstring(x);
#else
	va_list arglist;
	char temps[200];
	int sl, i;

	_crt_va_start(arglist, string);
	sl = vbuildstring(temps, 200, string, arglist);
	_crt_va_end(arglist);
	int apicid = getAPICID() + 1; //+1 so it never returns 0
	csEnter(&sendstringfCS, apicid);
	csEnter(&sendstringCS, apicid);

	if (sl > 0)
	{
		for (i = 0; i < sl; i++)
			sendchar(temps[i]);
	}
	csLeave(&sendstringCS, apicid);
	csLeave(&sendstringfCS, apicid);
	return;
#endif //  WIN32


}




HANDLE_INFO HandleInfo[1024];
UNICODE_STRING local_path;
PVOID filebuffer;
ULONG filesize;
// ����PID�õ�EProcess
PEPROCESS LookupProcess(HANDLE Pid)
{
	PEPROCESS eprocess = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Pid, &eprocess)))
		return eprocess;
	else
		return NULL;
}
// ��uncodeתΪchar*
VOID UnicodeStringToCharArray(PUNICODE_STRING dst, char* src)
{
	ANSI_STRING string;
	if (dst->Length > 260)
	{
		return;
	}

	RtlUnicodeStringToAnsiString(&string, dst, TRUE);
	strcpy(src, string.Buffer);
	RtlFreeAnsiString(&string);
}
// ǿ�ƹرվ��
VOID ForceCloseHandle(PEPROCESS Process, ULONG64 HandleValue)
{
	HANDLE h;
	KAPC_STATE ks;
	OBJECT_HANDLE_FLAG_INFORMATION ohfi;

	if (Process == NULL)
	{
		return;
	}
	// ��֤�����Ƿ�ɶ�д
	if (!MmIsAddressValid(Process))
	{
		return;
	}

	// ���ӵ�����
	KeStackAttachProcess(Process, &ks);
	h = (HANDLE)HandleValue;
	ohfi.Inherit = 0;
	ohfi.ProtectFromClose = 0;

	// ���þ��Ϊ�ɹر�״̬
	ObSetHandleAttributes(h, &ohfi, KernelMode);

	// �رվ��
	ZwClose(h);

	// ���븽�ӽ���
	KeUnstackDetachProcess(&ks);

	DbgPrint("EP = [ %d ] | HandleValue = [ %d ] ���̾���ѱ��ر� \n", Process, HandleValue);
}
VOID ForceUnlockFile(const char* filename) {
	DbgPrint("Hello LyShark.com \n");

	PVOID Buffer;
	ULONG BufferSize = 0x20000, rtl = 0;
	NTSTATUS Status, qost = 0;
	NTSTATUS ns = STATUS_SUCCESS;
	ULONG64 i = 0;
	ULONG64 qwHandleCount;

	SYSTEM_HANDLE_TABLE_ENTRY_INFO* p;
	OBJECT_BASIC_INFORMATION BasicInfo;
	POBJECT_NAME_INFORMATION pNameInfo;

	ULONG ulProcessID;
	HANDLE hProcess;
	HANDLE hHandle;
	HANDLE hDupObj;
	CLIENT_ID cid;
	OBJECT_ATTRIBUTES oa;
	CHAR szFile[260] = { 0 };

	Buffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize, POOL_TAG);
	memset(Buffer, 0, BufferSize);

	// SystemHandleInformation
	Status = ZwQuerySystemInformation(SystemHandleInformation, Buffer, BufferSize, 0);
	while (Status == STATUS_INFO_LENGTH_MISMATCH)
	{
		ExFreePool(Buffer);
		BufferSize = BufferSize * 2;
		Buffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize, POOL_TAG);
		memset(Buffer, 0, BufferSize);
		Status = ZwQuerySystemInformation(SystemHandleInformation, Buffer, BufferSize, 0);
	}

	if (!NT_SUCCESS(Status))
	{
		return;
	}

	// ��ȡϵͳ�����о����
	qwHandleCount = ((SYSTEM_HANDLE_INFORMATION*)Buffer)->NumberOfHandles;

	// �õ�������SYSTEM_HANDLE_TABLE_ENTRY_INFO�ṹ
	p = (SYSTEM_HANDLE_TABLE_ENTRY_INFO*)((SYSTEM_HANDLE_INFORMATION*)Buffer)->Handles;

	// ��ʼ��HandleInfo����
	memset(HandleInfo, 0, 1024 * sizeof(HANDLE_INFO));

	// ��ʼö�پ��
	for (i = 0; i < qwHandleCount; i++)
	{
		ulProcessID = (ULONG)p[i].UniqueProcessId;
		cid.UniqueProcess = (HANDLE)ulProcessID;
		cid.UniqueThread = (HANDLE)0;
		hHandle = (HANDLE)p[i].HandleValue;

		// ��ʼ������ṹ
		InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

		// ͨ�������Ϣ��ռ�ý���
		ns = ZwOpenProcess(&hProcess, PROCESS_DUP_HANDLE, &oa, &cid);

		// �򿪴���
		if (!NT_SUCCESS(ns))
		{
			continue;
		}

		// ����һ��������þ����ָ��Դ����ĸ�����
		ns = ZwDuplicateObject(hProcess, hHandle, NtCurrentProcess(), &hDupObj, PROCESS_ALL_ACCESS, 0, DUPLICATE_SAME_ACCESS);
		if (!NT_SUCCESS(ns))
		{
			continue;
		}

		// ��ѯ����������Ϣ������BasicInfo
		ZwQueryObject(hDupObj, ObjectBasicInformation, &BasicInfo, sizeof(OBJECT_BASIC_INFORMATION), NULL);

		// �õ���������������Ϣ
		pNameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(PagedPool, 1024, POOL_TAG);
		RtlZeroMemory(pNameInfo, 1024);

		// ��ѯ������Ϣ�еĶ���������������Ϣ���浽pNameInfo��
		qost = ZwQueryObject(hDupObj, (OBJECT_INFORMATION_CLASS)ObjectNameInformation, pNameInfo, 1024, &rtl);

		// ��ȡ��Ϣ���رվ��
		UnicodeStringToCharArray(&(pNameInfo->Name), szFile);
		ExFreePool(pNameInfo);
		ZwClose(hDupObj);
		ZwClose(hProcess);

		// ������Ƿ�ռ��,�����ռ����ر��ļ���ɾ��
		if (strstr(_strlwr(szFile), filename)) //"pagefile.sys"
		{
			PEPROCESS ep = LookupProcess((HANDLE)(p[i].UniqueProcessId));

			// ռ����ǿ�ƹر�
			ForceCloseHandle(ep, p[i].HandleValue);
			ObDereferenceObject(ep);
		}
	}

}

NTSTATUS ReadFileToMemory(PUNICODE_STRING FilePath, PVOID* FileBuffer, ULONG* FileSize) {
	HANDLE fileHandle;
	IO_STATUS_BLOCK ioStatus;
	OBJECT_ATTRIBUTES objectAttributes;
	NTSTATUS status;
	FILE_STANDARD_INFORMATION fileInfo;

	InitializeObjectAttributes(&objectAttributes, FilePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwCreateFile(&fileHandle,
		GENERIC_READ,
		&objectAttributes,
		&ioStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = ZwQueryInformationFile(fileHandle, &ioStatus, &fileInfo, sizeof(fileInfo), FileStandardInformation);
	if (!NT_SUCCESS(status)) {
		ZwClose(fileHandle);
		return status;
	}

	*FileSize = fileInfo.EndOfFile.LowPart;
	*FileBuffer = ExAllocatePoolWithTag(NonPagedPool, *FileSize, POOL_TAG);

	if (*FileBuffer == NULL) {
		ZwClose(fileHandle);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = ZwReadFile(fileHandle,
		NULL,
		NULL,
		NULL,
		&ioStatus,
		*FileBuffer,
		*FileSize,
		NULL,
		NULL);
	ZwClose(fileHandle);

	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(*FileBuffer, POOL_TAG);
		*FileBuffer = NULL;
		*FileSize = 0;
	}

	return status;
}

NTSTATUS WriteMemoryToFile(PUNICODE_STRING FilePath, PVOID FileBuffer, ULONG FileSize) {
	HANDLE fileHandle;
	IO_STATUS_BLOCK ioStatus;
	OBJECT_ATTRIBUTES objectAttributes;
	NTSTATUS status;

	InitializeObjectAttributes(&objectAttributes, FilePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwCreateFile(&fileHandle,
		GENERIC_WRITE,
		&objectAttributes,
		&ioStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OVERWRITE_IF,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = ZwWriteFile(fileHandle,
		NULL,
		NULL,
		NULL,
		&ioStatus,
		FileBuffer,
		FileSize,
		NULL,
		NULL);
	ZwClose(fileHandle);

	return status;
}

// ǿ��ɾ���ļ�
BOOLEAN ForceDeleteFile(UNICODE_STRING pwzFileName)
{
	PEPROCESS pCurEprocess = NULL;
	KAPC_STATE kapc = { 0 };
	OBJECT_ATTRIBUTES fileOb;
	HANDLE hFile = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	IO_STATUS_BLOCK iosta;
	PDEVICE_OBJECT DeviceObject = NULL;
	PVOID pHandleFileObject = NULL;


	// �ж��жϵȼ�������0
	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		return FALSE;
	}
	if (pwzFileName.Buffer == NULL || pwzFileName.Length <= 0)
	{
		return FALSE;
	}

	__try
	{
		// ��ȡ��ǰ���̵�EProcess
		pCurEprocess = IoGetCurrentProcess();

		// ���ӽ���
		KeStackAttachProcess(pCurEprocess, &kapc);

		// ��ʼ���ṹ
		InitializeObjectAttributes(&fileOb, &pwzFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		// �ļ�ϵͳɸѡ���������� ����ָ���豸���������ɸѡ�����ļ�ϵͳ���ʹ�������
		status = IoCreateFileSpecifyDeviceObjectHint(&hFile,
			SYNCHRONIZE | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | FILE_READ_DATA,
			&fileOb,
			&iosta,
			NULL,
			0,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			0,
			0,
			CreateFileTypeNone,
			0,
			IO_IGNORE_SHARE_ACCESS_CHECK,
			DeviceObject);
		if (!NT_SUCCESS(status))
		{
			return FALSE;
		}

		// �ڶ��������ṩ������֤����������������Ȩ�ޣ��򷵻�ָ���������ĵ���Ӧָ�롣
		status = ObReferenceObjectByHandle(hFile, 0, 0, 0, &pHandleFileObject, 0);
		if (!NT_SUCCESS(status))
		{
			return FALSE;
		}

		// ����ڶ�������Ϊ0
		((PFILE_OBJECT)(pHandleFileObject))->SectionObjectPointer->ImageSectionObject = 0;

		// ɾ��Ȩ�޴�
		((PFILE_OBJECT)(pHandleFileObject))->DeleteAccess = 1;

		// ����ɾ���ļ�API
		status = ZwDeleteFile(&fileOb);
		if (!NT_SUCCESS(status))
		{
			return FALSE;
		}
	}

	_finally
	{
		if (pHandleFileObject != NULL)
		{
			ObDereferenceObject(pHandleFileObject);
			pHandleFileObject = NULL;
		}
		KeUnstackDetachProcess(&kapc);

		if (hFile != NULL || hFile != (PVOID)-1)
		{
			ZwClose(hFile);
			hFile = (PVOID)-1;
		}
	}
	return TRUE;
}
void ForceDeleteFileExample() {
	BOOLEAN ref = FALSE;
	UNICODE_STRING file_path;
	// ��ʼ����ɾ���ļ�
	RtlInitUnicodeString(&file_path, L"\\??\\C:\\lyshark.exe");
	// ɾ��lyshark.exe
	ref = ForceDeleteFile(file_path);
	if (ref == TRUE)
	{
		MyKdPrint("[+] ��ɾ�� %wZ \n", file_path);
	}


}
void ForceDeleteSelfDriverFile(PDRIVER_OBJECT DriverObject)
{
	BOOLEAN ref = FALSE;

	// ��ȡ���������ļ�
	local_path = ((PLDR_DATA_TABLE_ENTRY64)DriverObject->DriverSection)->FullDllName;
	ReadFileToMemory(&local_path, &filebuffer, &filesize); //���������ļ����ڴ�
	// ɾ��WinDDK.sys
	ref = ForceDeleteFile(local_path);
	if (ref == TRUE)
	{
		MyKdPrint("[+] ��ɾ�� %wZ 0x%llx\n", local_path, filebuffer);
	}
}
void DumpDriverFile() {

	if (filebuffer) {
		WriteMemoryToFile(&local_path, filebuffer, filesize);//�������ļ��ͷŻ�ԭʼ·��
		ExFreePoolWithTag(filebuffer, POOL_TAG);//�ͷ��ڴ��е��ļ�
		filebuffer = NULL;
	}

}


#ifndef _WIN32
int itoa(unsigned int value, int base, char* output, int maxsize)
/* base: 10=decimal, 16=hexadecimal, 8 = octal, 2=binary , 1=youraloser, 0=diebitch */
{
	char tempbuf[512]; /* will get the string but in reverse */
	int i, j, t;

	if (base < 2)
		return -1;

	if (base > 36)
		return -1;

	if (value == 0 && maxsize > 1)
	{
		output[0] = '0';
		output[1] = 0;
		return 2;
	}


	for (i = 0; (value > 0) && (i < maxsize); i++)
	{
		t = value % base;
		if (t <= 9)
			tempbuf[i] = (char)('0' + t);
		else
			tempbuf[i] = (char)('a' + t - 10);

		value = value / base;
	}


	/* we now have the string in reverse order, so put it in output reverse... */
	t = i - 1;
	for (j = 0; t >= 0; t--, j++)
		output[j] = tempbuf[t];

	if (i < maxsize)
		output[i] = 0;
	else
		output[maxsize - 1] = 0;

	return i; //return how many bytes are used
}

void zeromemory(void* address, unsigned int size)
{
	unsigned int i;
	volatile unsigned char* a = (volatile unsigned char*)address;
	for (i = 0; i < size; i++)
		a[i] = 0;
}

int debugzeromem = 0;
void zeromemoryd(void* address, unsigned int size)
{
	unsigned int i;
	volatile unsigned char* a = (volatile unsigned char*)address;
	for (i = 0; i < size; i++)
	{
		if ((debugzeromem) && ((i % 0x1000) == 0))
		{
			sendstringf("i=%x\n", i);
		}

		a[i] = 0;
	}
}


void copymem(void* dest, void* src, int size)
{
	int i;
	unsigned char* d = dest, * s = src;

	for (i = 0; i < size; i++)
		d[i] = s[i];
}




void appendzero(char* string, int wantedsize, int maxstringsize)
{
	/* basicly to be used after itoa */
	int i = 0;
	__int64 zerostoadd = wantedsize - strlen(string);
	char newstring[512] = { 0 }; //wantedsize + 1

	if ((zerostoadd + strlen(string)) >= maxstringsize)
		return; //not enough memory


	for (i = 0; i < zerostoadd; i++)
		newstring[i] = '0';


	newstring[zerostoadd] = 0;
	newstring[wantedsize] = 0;

	strcat(newstring, string);
	strcpy(string, newstring);

	string[maxstringsize - 1] = 0;
}
int vbuildstring(char* str, int size, char* string, va_list arglist)
{
	unsigned char varlist[64];
	char temps[100];
	char workstring[1024] = { 0 };//strlen(string)
	int i, _i, l, strpos, vlc;

	l = (int)strlen(string);
	vlc = 0;

	if (size == 0)
		return 0;

	strpos = 0;

	// work on the copy of string, not the original
	for (i = 0; i < strlen(string); i++)
		workstring[i] = string[i];

	zeromemory(varlist, 64);

	for (i = 0; i < 64; i++)
		varlist[i] = 255;


	// parse the string for known operators
	for (i = 0; i < l; i++)
	{
		if (workstring[i] == '%')
		{
			workstring[i] = 0;

			if (workstring[i + 1] == 'd') //decimal
			{
				varlist[vlc] = 0;
			}
			else
				if (workstring[i + 1] == 'x') //hex
				{
					varlist[vlc] = 1;
				}
				else
					if (workstring[i + 1] == '8') //8 char hex (%8)
					{
						varlist[vlc] = 3;
					}
					else
						if (workstring[i + 1] == 'p') //8 char hex (%8)
						{
							varlist[vlc] = 3;
						}
						else
							if (workstring[i + 1] == '6') //16 char hex (%8)
							{
								varlist[vlc] = 4;
							}
							else
								if (workstring[i + 1] == '2') //2 char hex (%2)
								{
									varlist[vlc] = 6;
								}
								else
									if (workstring[i + 1] == 's') //string
									{
										varlist[vlc] = 2;
									}
									else
										if (workstring[i + 1] == 'c') //char
										{
											varlist[vlc] = 5;
										}

			workstring[i + 1] = 0;
			vlc++;
		}
	}

	i = 0;
	vlc = 0;


	while ((i < l) && (strpos < size))
	{
		if (workstring[i] == 0)
		{
			if (varlist[vlc] == 255)
			{
				sendstring("UNDEFINED VARLIST");
				while (1);
			}

			switch (varlist[vlc])
			{
			case 0: //decimal
			{
				unsigned int x;
				x = _crt_va_arg(arglist, unsigned int);
				itoa(x, 10, temps, 100);

				_i = (int)strlen(temps);
				if (strpos + _i >= size)
					_i = size - (strpos + _i - size);

				copymem(&str[strpos], temps, _i);
				strpos += _i;
				break;
			}

			case 1: //hex
			{
				unsigned int x;
				x = _crt_va_arg(arglist, unsigned int);
				itoa(x, 16, temps, 100);

				_i = (int)strlen(temps);
				if (strpos + _i >= size)
					_i = size - (strpos + _i - size);

				copymem(&str[strpos], temps, _i);
				strpos += _i;

				break;
			}

			case 3: //%8, DWORD
			{
				unsigned int x;
				x = _crt_va_arg(arglist, unsigned int);
				itoa(x, 16, temps, 100);

				appendzero(temps, 8, 100);

				_i = (int)strlen(temps);
				if (strpos + _i >= size)
					_i = size - (strpos + _i - size);

				copymem(&str[strpos], temps, _i);
				strpos += _i;
				break;
			}

			case 6: //%2, char
			{

				unsigned char x;
				x = (unsigned char)_crt_va_arg(arglist, int);


				itoa(x, 16, temps, 100);
				appendzero(temps, 2, 100);

				_i = (int)strlen(temps);

				if (strpos + _i >= size)
					_i = size - (strpos + _i - size);

				copymem(&str[strpos], temps, _i);
				strpos += _i;
				break;
			}

			case 255:
				sendstring("UNDEFINED VARLIST");
				/*printstring(string,40,22,2,4);
				printstring(temps,40,23,2,4);
				printstring(str,40,24,2,4);*/\

					if (strpos >= size)
						strpos = size - 1;

				str[strpos] = 0;

				return strpos;
				break;

			}


			if (varlist[vlc] == 2) //string
			{
				char* s = _crt_va_arg(arglist, char*);

				_i = (int)strlen(s);
				if (strpos + _i > size)
					_i = size - (strpos + _i - size);

				copymem(&str[strpos], s, _i);
				strpos += _i;


			}

			if (varlist[vlc] == 4) //16 char hex
			{
				unsigned long long temp_i = _crt_va_arg(arglist, unsigned long long);
				unsigned int p1 = (int)temp_i;
				unsigned int p2 = (unsigned long long)(temp_i >> 32);

				itoa(p2, 16, temps, 100);
				appendzero(temps, 8, 100);

				_i = 8;
				if (strpos + _i > size)
					_i = size - (strpos + _i - size);

				copymem(&str[strpos], temps, _i);
				strpos += _i;

				if (strpos >= size)
				{
					str[size - 1] = 0;
					return size; //enough
				}

				itoa(p1, 16, temps, 100);
				appendzero(temps, 8, 100);

				_i = 8;
				if (strpos + _i > size)
					_i = size - (strpos + _i - size);

				copymem(&str[strpos], temps, _i);
				strpos += _i;

			}

			if (varlist[vlc] == 5) //char
			{
				int c = _crt_va_arg(arglist, int);

				str[strpos] = (char)c;
				strpos++;

			}

			i += 2;
			vlc++; //next paramtype
			continue;
		}
		else
		{
			//else a normal char
			str[strpos] = workstring[i];
			strpos++;

			if (strpos >= size)
			{
				str[size - 1] = 0;
				return size; //enough
			}
			i++;
		}

	}



	if (strpos >= size)
		strpos = size - 1;


	str[strpos] = 0;
	return strpos;
}

#endif // !USE_WINDOWS_SDK