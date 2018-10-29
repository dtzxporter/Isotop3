#include "stdafx.h"

static std::vector<HMODULE> modules;

struct ProxyMapEntry
{
	const char* process;
	std::vector<const char*> libraries;
};

static ProxyMapEntry proxy_map[] =
{
	{"EXE_NAME.exe",		{"game_mod.dll"}},
};

BOOL WINAPI Proxy_Init(HINSTANCE hInst, DWORD reason)
{
	if (reason != DLL_PROCESS_ATTACH)
		return FALSE;

	char name[MAX_PATH];
	GetModuleFileNameA(GetModuleHandleA(NULL), name, _countof(name));

	char *p = strrchr(name, '\\');
	if (!p)
		return FALSE;

	for (int i = 0; name[i]; i++)
	{
		name[i] = p[i + 1];
	}

	for (const auto& entry : proxy_map)
	{
		if (_stricmp(name, entry.process) != 0)
			continue;

		for (const auto& library : entry.libraries)
		{
			HMODULE h = LoadLibraryA(library);
			if (!h)
			{
				char msg[1024];
				const auto err = GetLastError();
				const auto offset = sprintf_s(msg, "Failed to load library '%s'\n", library);
				FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
							   NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
							   msg + offset, (sizeof(msg) / sizeof(decltype(*msg))) - offset, NULL);
				MessageBoxA(0, msg, 0, 0);
				
				// We were unable to load the required mod
				// Kill the process
				exit(0);

				return FALSE;
			}

			modules.push_back(h);
		}

		break;
	}

	return TRUE;
};

BOOL WINAPI Proxy_Free(HINSTANCE hInst, DWORD reason)
{
	if (reason != DLL_PROCESS_DETACH)
		return FALSE;

	while (modules.size())
	{
		auto h = modules[modules.size() - 1];
		modules.pop_back();

		// Should we add error handling here?
		FreeLibrary(h);
	}

	return TRUE;
}
