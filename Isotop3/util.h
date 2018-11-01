#pragma once

#include <windows.h>
#include <stdint.h>

void PatchMemory(ULONG_PTR Address, PBYTE Data, SIZE_T Size);
void WriteCall(uintptr_t Address, uintptr_t Target);
void WriteJump(uintptr_t Address, uintptr_t Target);