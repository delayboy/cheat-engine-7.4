#pragma once
#include "MyCEHelper.h"

const char* InitMyCeMiniUi(const char* ini_text, bool wait_close);
void __stdcall mainmenuplugin(void);
int lua_plugin_print(lua_State* L);
