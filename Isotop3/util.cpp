#include "util.h"
#include "Detours.h"

#pragma comment(lib, "detours.lib")

void PatchMemory(ULONG_PTR Address, PBYTE Data, SIZE_T Size)
{
	DWORD d = 0;
	VirtualProtect((LPVOID)Address, Size, PAGE_EXECUTE_READWRITE, &d);

	for (SIZE_T i = Address; i < (Address + Size); i++)
		*(volatile BYTE *)i = *Data++;

	VirtualProtect((LPVOID)Address, Size, d, &d);
	FlushInstructionCache(GetCurrentProcess(), (LPVOID)Address, Size);
}

void WriteCall(uintptr_t Address, uintptr_t Target)
{
	Detours::X64::DetourFunction((PBYTE)Address, (PBYTE)Target);
	PatchMemory(Address, (PBYTE)"\xE8", 1);
}

void WriteJump(uintptr_t Address, uintptr_t Target)
{
	Detours::X64::DetourFunction((PBYTE)Address, (PBYTE)Target);
}