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
#include <vector>
#include <fstream>//ifstream读文件，ofstream写文件，fstream读写文件
#include <sstream>
#pragma comment(lib, "Psapi.lib ")
#pragma  comment(lib, "shell32.lib")



std::string getBaseName(LPCSTR filePath);

std::string getFileTail(LPCSTR filePath);

LPCSTR chooseFile();

std::string getLnkFormPath(std::string filePath);

FILE* generateFileStream(const char* path);
bool fileExist(const char* path);
std::map<std::string, std::string> GetManyLuaScriptFromTxt();
char* getDynamicChars(std::string str);

std::vector<std::pair<std::string,std::string>>  GetManyLuaScriptFromResource(HMODULE hModule);
char* get_cwd_file(char* nowPath, const char* file_name);