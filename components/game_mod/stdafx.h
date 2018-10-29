#pragma once

#pragma comment(lib, "detours.lib")
#include "../shared/detours/Detours.h"

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <intrin.h>
#include <Psapi.h>
#include <shellapi.h>
#include <winsock2.h>
#include <time.h>
#include <vector>
#include <unordered_map>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")

//
// Shared files
//
#include "../shared/shared_utility.h"
#include "../shared/shared_version.h"

#include "../shared/minidx9/Include/d3dx9.h"
#pragma comment(lib, "../shared/minidx9/Lib/x86/d3dx9.lib")

#include "string.h"

#define GM_USE_PROXY   true
