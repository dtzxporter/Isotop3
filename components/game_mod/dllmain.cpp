#define G_VERSION 0, 1, 0
#include "stdafx.h"

BOOL GameMod_Init(HMODULE hModule)
{
	//
	// Disable STDOUT buffering
	//
	setvbuf(stdout, nullptr, _IONBF, 0);

	return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if(ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hModule);
		return GameMod_Init(hModule); 
	}
	else if(ul_reason_for_call == DLL_PROCESS_DETACH)
	{
		// Pass
	}

	return TRUE;
}