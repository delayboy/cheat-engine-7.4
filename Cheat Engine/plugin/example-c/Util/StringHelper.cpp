#include "MyCEHelper.h"
#include "StringHelper.h"

char* getDynimicChars(const char* s)
{
	int length = strlen(s);
	char* newChars = (char*)malloc(sizeof(char) * length);
	if (newChars) strcpy(newChars, s);
	return newChars;


}
std::wstring s2ws(const std::string& s)
{
	std::string curlLocale = setlocale(LC_ALL, NULL);
	setlocale(LC_ALL, "chs");
	const char* _Source = s.c_str();
	size_t _Dsize = s.size() + 1;

	wchar_t* _Dest = new wchar_t[_Dsize];
	size_t i;
	mbstowcs_s(&i, _Dest, _Dsize, _Source, s.size());
	std::wstring result = _Dest;
	delete[] _Dest;
	setlocale(LC_ALL, curlLocale.c_str());
	return result;
}
__int64 powi(__int64 base, int exponent)
{
	__int64 res = 1;
	for (int i = 1; i <= exponent; i++)
	{
		res = res * base;
	}
	return res;
}
__int64 strToHex(char* s)
{
	__int64 strLen = strlen(s);
	__int64 hex = 0x0;
	for (int i = 0; i < strLen; i++)
	{
		char temp = s[i];
		if ((temp >= 48) && (temp <= 57))
		{
			temp = temp - 48;
		}
		else if ((temp >= 97) && (temp <= 102))
		{
			temp = temp - 87;
		}
		else if ((temp >= 65) && (temp <= 70))
		{
			temp = temp - 55;
		}
		else if (temp == 120 && i == 1 && s[0] == '0')
		{
			temp = 0;
		}

		else return 0;
		hex = hex + temp * (powi(16, strLen - 1 - i));
	}
	return hex;
}
