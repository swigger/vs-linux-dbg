#pragma once
#define _WIN32_WINNT 0x0A00
#define NOMINMAX
#include <SDKDDKVer.h>
#include <WinSock2.h>
#include <atlbase.h>
#include <atlcom.h>
#include <Windows.h>
#include <stdlib.h>
#include <stdint.h>


#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <optional>
#include <algorithm>
#include <functional>

using std::string;
using std::vector;
using std::map;
using std::unordered_map;
typedef const std::string& crefstr;
typedef SSIZE_T ssize_t;
