#pragma once
#include<iostream>
#include <fstream>//ifstream读文件，ofstream写文件，fstream读写文件
#include <vector>
#include<Windows.h>
#include <sstream>
#include <stdio.h>
#include <windows.h>
#include <io.h>
#include <process.h>
#include <cstdlib>
#pragma comment(lib,"ws2_32.lib")

typedef struct _PakageHeader;
typedef struct _NetworkParam;

#define VALID_HEADER 0x123456
typedef void(__stdcall* TCPCALLBACK)(_NetworkParam* param, _PakageHeader* pk_header, std::vector<char> data);
typedef struct _PakageHeader {
    __int64 valid;
    __int64 pkLength;
    __int64 code;
} PakageHeader, * PPakageHeader;

typedef struct _NetworkParam {
    const char* host;
    int port;
    HANDLE thread_handle;
    SOCKET client_socket;
    TCPCALLBACK callback;
}NetworkParam, * PNetworkParam;

EXTERN_C{
    void DefaultTcpCallback(PNetworkParam param, PPakageHeader pk_header,std::vector<char> data);

    DWORD __stdcall ServerSocketThread(LPVOID lp);

    DWORD __stdcall ClientSocketThread(LPVOID lp);

    void StartTcpServer(int port, TCPCALLBACK callback);

    void StartTcpClient(const char* host, int port, TCPCALLBACK callback);

    void StopTcpSever();

    void StopTcpClient();
    void TcpSendStr(SOCKET client_socket, std::string content, int code = 1);

}
