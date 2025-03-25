#include "MyTcpHelper.h"

NetworkParam tcp_client_param = { 0 };
NetworkParam tcp_server_param = { 0 };

void DefaultTcpCallback(PNetworkParam param, PPakageHeader pk_header, std::vector<char> data) {
    // 向客户端发送响应

    if (pk_header->code == 1) {
        data.push_back('\0');
        printf("recv:%s\n",data.data());
    }
    if (param->client_socket) {
        char response[1] = { 0 };
        if (send(param->client_socket, response, 1, 0) < 0) {
            std::cerr << "Failed to send response." << std::endl;

        }
    }
  
}

DWORD __stdcall ServerSocketThread(LPVOID lp)
{

    PNetworkParam param = (PNetworkParam)lp;
    //初始化DLL
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    SOCKET serverSocket, clientSocket;
    struct sockaddr_in serverAddress, clientAddress;
    char buffer[512];

    // 创建套接字
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        std::cerr << "Failed to create socket." << std::endl;
        return -1;
    }
    u_long iMODE = 0;//1为非阻塞，0为阻塞
    ioctlsocket(serverSocket, FIONBIO, &iMODE);//设置recvfrom是否为阻塞
    // 设置服务器地址
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(param->port);
    int timeout = 1000*60*60; //1小时超时
    if (setsockopt(serverSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) == -1) {
        printf("setsockopt failed:");
    }
    // 绑定套接字到指定地址和端口
    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        std::cerr << "Failed to bind socket." << std::endl;
        return -1;
    }

    // 监听连接
    listen(serverSocket, 3);
    std::vector<char> headerBuffer;
    std::vector<char> dataBuffer;
    PakageHeader header;
    clientSocket = NULL;
    while (1)
    {

        // 从客户端接收数据
        int bytesRead = -1;
        if (clientSocket != NULL) {
            bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
        }
       
        if (bytesRead <= 0) {
            std::cerr << "Failed to read from socket." << std::endl;
            printf("error=%d\n", WSAGetLastError()); // SOCKET_ERROR == WSAETIMEDOUT
            //关闭套接字
            param->client_socket = NULL;
            closesocket(clientSocket);
            clientSocket = NULL;
            headerBuffer.clear();
            dataBuffer.clear();
            memset(&header, 0, sizeof(PakageHeader));//清空暂存header
            Sleep(2000);//等待清理

            //接受客户端连接+掉线重连
            std::cout << "Server started. Waiting for incoming connections..." << std::endl;
            int clientAddressSize = sizeof(clientAddress);
            clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddress, &clientAddressSize);
            if (clientSocket < 0) {
                std::cerr << "Failed to accept connection." << std::endl;
            }
            else {
                param->client_socket = clientSocket;
            }
        }
        else {
            for (int i = 0; i < bytesRead; i++)//从buffer中依次读取数据
            {
                //包头还没找到或还未缓存
                if (header.valid != VALID_HEADER && headerBuffer.size() < sizeof(PakageHeader))
                {
                    headerBuffer.push_back(buffer[i]);
                }
                else {
                    PPakageHeader pheader = (PPakageHeader)headerBuffer.data();

                    if (pheader->valid == VALID_HEADER)
                    {
                        //保存当前头
                        memcpy_s(&header, sizeof(PakageHeader), headerBuffer.data(), sizeof(PakageHeader));
                        headerBuffer.clear();
                        //填充数据Buffer
                        if (dataBuffer.size() < pheader->pkLength)
                        {
                            dataBuffer.push_back(buffer[i]);
                            //printf("%lld - %lld\n", pheader->pkLength, dataBuffer.size());

                        }
                        if (dataBuffer.size() >= pheader->pkLength) //已经读取完成
                        {
                            param->callback(param, &header, dataBuffer);//构建出完整包
                            headerBuffer.clear();//清空header缓冲区
                            //headerBuffer.push_back(buffer[i]);//将当前bit存入header
                            memset(&header, 0, sizeof(PakageHeader));//清空暂存header
                            dataBuffer.clear();//清空数据缓冲区

                        }

                    }
                    else { //包头数量够了但找的不对
                        headerBuffer.erase(headerBuffer.begin());//删除首个元素，元素依次顺移
                        headerBuffer.push_back(buffer[i]); // 从后面再取一个数，看看校验位能不能满足
                    }


                }

            }

        }

    }

    // 关闭套接字
    closesocket(clientSocket);
    closesocket(serverSocket);
    WSACleanup();
    param->thread_handle = NULL;

}

DWORD __stdcall ClientSocketThread(LPVOID lp)
{
    PNetworkParam param = (PNetworkParam)lp;
    //初始化DLL
    WSADATA wsaData;
    bool hasRecieved = true;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    //
    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);//SOCK_DGRAM,IPPROTO_UDP
    if (clientSocket < 0) {
        perror("socket error");
        exit(-1);
    }

    u_long iMODE = 0;//1为非阻塞，0为阻塞
    ioctlsocket(clientSocket, FIONBIO, &iMODE);//设置recvfrom是否为阻塞
    int n;
    struct sockaddr_in serv;
    serv.sin_family = AF_INET;
    serv.sin_port = htons(param->port);
    ULONG s = inet_addr(param->host);
    serv.sin_addr.s_addr = s;
    char buff[500] = { 0 };
    int timeout = 20000; //3s
    if (setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) == -1) {
        printf("setsockopt failed:");
    }
    if (INVALID_SOCKET == (::connect(clientSocket, (sockaddr*)&serv, sizeof(sockaddr_in))))
    {
        printf("Connect to Server Error!\n");
        return -1;
    }
    std::vector<char> headerBuffer;
    std::vector<char> dataBuffer;
    PakageHeader header = { 0 };
    char buffer[512];
    param->client_socket = clientSocket;
    while (1)
    {

        // 从客户端接收数据
        int bytesRead = -1;
        if (clientSocket != NULL) {
            bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
        }

        if (bytesRead <= 0) {
            std::cerr << "Failed to read from socket." << std::endl;
            //关闭套接字
            param->client_socket = NULL;
            closesocket(clientSocket);
            clientSocket = NULL;
            headerBuffer.clear();
            dataBuffer.clear();
            memset(&header, 0, sizeof(PakageHeader));//清空暂存header
            break;
        }
        else {
            for (int i = 0; i < bytesRead; i++)//从buffer中依次读取数据
            {
                //包头还没找到或还未缓存
                if (header.valid != VALID_HEADER && headerBuffer.size() < sizeof(PakageHeader))
                {
                    headerBuffer.push_back(buffer[i]);
                }
                else {
                    PPakageHeader pheader = (PPakageHeader)headerBuffer.data();

                    if (pheader->valid == VALID_HEADER)
                    {
                        //保存当前头
                        memcpy_s(&header, sizeof(PakageHeader), headerBuffer.data(), sizeof(PakageHeader));
                        headerBuffer.clear();
                        //填充数据Buffer
                        if (dataBuffer.size() < pheader->pkLength)
                        {
                            dataBuffer.push_back(buffer[i]);

                        }
                        if (dataBuffer.size() >= pheader->pkLength) //已经读取完成
                        {
                            param->callback(param, &header,dataBuffer);//构建出完整包
                            headerBuffer.clear();//清空header缓冲区
                            //headerBuffer.push_back(buffer[i]);//将当前bit存入header
                            memset(&header, 0, sizeof(PakageHeader));//清空暂存header
                            dataBuffer.clear();//清空数据缓冲区

                        }

                    }
                    else { //包头数量够了但找的不对
                        headerBuffer.erase(headerBuffer.begin());//删除首个元素，元素依次顺移
                        headerBuffer.push_back(buffer[i]); // 从后面再取一个数，看看校验位能不能满足
                    }


                }

            }

        }

    }
 
    closesocket(clientSocket);
    WSACleanup();
    param->thread_handle = NULL;
}
void TcpSendStr(SOCKET client_socket,std::string content,int code) {
    
    if (client_socket==-1) client_socket = tcp_server_param.client_socket;
    else if (client_socket == -2) client_socket = tcp_client_param.client_socket;
    if (client_socket) {
        std::vector<char> buffer;
        size_t str_len = content.size();
        PakageHeader header = { VALID_HEADER,str_len,code};
        buffer.resize(sizeof(PakageHeader) + str_len);

        memcpy_s(buffer.data(), sizeof(PakageHeader), &header, sizeof(PakageHeader));
        memcpy_s(buffer.data() + sizeof(PakageHeader), buffer.size(), content.data(), str_len);
        if (send(client_socket, buffer.data(), buffer.size(), 0) < 0) {
            std::cerr << "Failed to send response." << std::endl;
        }
    }
}
void StartTcpServer(int port,TCPCALLBACK callback)
{
    tcp_server_param.port = port;
    if(callback)tcp_server_param.callback = callback;
    else tcp_server_param.callback = DefaultTcpCallback;
    tcp_server_param.thread_handle = CreateThread(NULL, 0, ServerSocketThread, (LPVOID)&tcp_server_param, 0, NULL);
}

void StartTcpClient(const char* host, int port, TCPCALLBACK callback)
{
    tcp_client_param.port = port;
    tcp_client_param.host = host;
    if (callback)tcp_client_param.callback = callback;
    else tcp_client_param.callback = DefaultTcpCallback;
    tcp_client_param.thread_handle = CreateThread(NULL, 0, ClientSocketThread, (LPVOID)&tcp_client_param, 0, NULL);
}


void StopTcpSever()
{
    if (tcp_server_param.thread_handle)CloseHandle(tcp_server_param.thread_handle);
    tcp_server_param.thread_handle = NULL;
}


void StopTcpClient()
{
    if (tcp_client_param.thread_handle)CloseHandle(tcp_client_param.thread_handle);
    tcp_client_param.thread_handle = NULL;

}