#include <windows.h>
#include <stdio.h>
#include <mutex>
#include "util.h"

#pragma comment(lib, "ws2_32.lib")

uintptr_t g_ModuleBase;
FILE *g_OutFile;
FILE *g_CurlOutFile;

__int64 hk_sub_142B1B0A0(void *a1, __int64 a2)
{
	static __int64 useless = 1;

	// Seems to be returning a C++ iterator?
	*(__int64 *)(a2 + 0) = 0;
	*(__int64 *)(a2 + 8) = 0;

	return (__int64)&useless;
}

thread_local char TLS_LargeBuffer[8192];

__int64 hk_sub_142B1ACE0(__int64 a1)
{
	static std::mutex m;

	m.lock();
	{
		// Destructor call from hk_sub_142B1AEE0
		fprintf(g_OutFile, "%s\n", TLS_LargeBuffer);
	}
	m.unlock();

	return 0;
}

struct FmtMemoryStrData
{
	__int64 unused2;	// 0x60
	const char *data;	// 0x68
	size_t rawLen;		// 0x70
	size_t allocatedLen;// 0x78
};

struct FmtMemoryBufferData
{
	char pad[0x58];			// 0x00
	__int64 unused1;		// 0x58
	FmtMemoryStrData *Data;	// 0x60
	char unknown[1000];
};

__int64(*sub_142B1AEE0)(void *a1, void *a2, const char *Filename, int line, int type);
__int64 hk_sub_142B1AEE0(void *a1, void *a2, const char *Filename, int line, int type)
{
	thread_local FmtMemoryBufferData bd;
	thread_local FmtMemoryStrData sd;

	bd.unused1 = 1;
	bd.Data = &sd;
	bd.Data->unused2 = 1;
	bd.Data->data = TLS_LargeBuffer;
	bd.Data->rawLen = 0;
	bd.Data->allocatedLen = 8192;

	memset(TLS_LargeBuffer, 0, sizeof(TLS_LargeBuffer));
	return (__int64)&bd;
}

void hk_sub_142B1B870(__int64 a1)
{
	__try
	{
		sprintf_s(TLS_LargeBuffer, "%s: %s", *(const char **)(a1 + 0x10), *(const char **)(a1 + 0x20));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		memset(TLS_LargeBuffer, 0, sizeof(TLS_LargeBuffer));
	}

	hk_sub_142B1ACE0(0);
}

typedef void CURL;

typedef enum
{
	CURLINFO_TEXT = 0,
	CURLINFO_HEADER_IN,    /* 1 */
	CURLINFO_HEADER_OUT,   /* 2 */
	CURLINFO_DATA_IN,      /* 3 */
	CURLINFO_DATA_OUT,     /* 4 */
	CURLINFO_SSL_DATA_IN,  /* 5 */
	CURLINFO_SSL_DATA_OUT, /* 6 */
	CURLINFO_END
} curl_infotype;

void CurlDump(const char *text, FILE *stream, unsigned char *ptr, size_t size)
{
	size_t i;
	size_t c;
	unsigned int width = 0x10;

	fprintf(stream, "%s, %10.10ld bytes (0x%8.8lx)\n",
		text, (long)size, (long)size);

	for (i = 0; i < size; i += width) {
		fprintf(stream, "%4.4lx: ", (long)i);

		/* show hex to the left */
		for (c = 0; c < width; c++) {
			if (i + c < size)
				fprintf(stream, "%02x ", ptr[i + c]);
			else
				fputs("   ", stream);
		}

		/* show data on the right */
		for (c = 0; (c < width) && (i + c < size); c++) {
			char x = (ptr[i + c] >= 0x20 && ptr[i + c] < 0x80) ? ptr[i + c] : '.';
			fputc(x, stream);
		}

		fputc('\n', stream); /* newline */
	}
}

int CurlTrace(CURL *handle, curl_infotype type, char *data, size_t size, void *userp)
{
	const char *text;
	(void)handle; /* prevent compiler warning */
	(void)userp;

	switch (type) {
	case CURLINFO_TEXT:
		fprintf(g_CurlOutFile, "== Info: %s", data);
	default: /* in case a new one is introduced to shock us */
		return 0;

	case CURLINFO_HEADER_OUT:
		text = "=> Send header";
		break;
	case CURLINFO_DATA_OUT:
		text = "=> Send data";
		break;
	case CURLINFO_SSL_DATA_OUT:
		text = "=> Send SSL data";
		break;
	case CURLINFO_HEADER_IN:
		text = "<= Recv header";
		break;
	case CURLINFO_DATA_IN:
		text = "<= Recv data";
		break;
	case CURLINFO_SSL_DATA_IN:
		text = "<= Recv SSL data";
		break;
	}

	CurlDump(text, g_CurlOutFile, (unsigned char *)data, size);
	return 0;
}

int hk_curl_easy_setopt(void *curl, int option, void *data)
{
	if (!curl)
		return 43;

	// Proxy
	// hk_curl_easy_setopt(curl, 10004, (void*)"http://127.0.0.1:8888");

	if (option == 10002)
	{
		const char *url = (const char *)data;
		fprintf(g_OutFile, "Loading CURL url: %s\n", url);

		//hk_curl_easy_setopt(curl, 10037, (void *)fout);		// CURLOPT_STDERR
		hk_curl_easy_setopt(curl, 41, (void *)1);				// CURLOPT_VERBOSE
		hk_curl_easy_setopt(curl, 20094, (void *)&CurlTrace);	// CURLOPT_DEBUGFUNCTION

		if (strstr(url, "/bps/pub/ticket"))
		{
			data = (void *)"http://localhost/bps/pub/ticket";
		}

		if (strstr(url, "/bps/pub/v2/login"))
		{
			data = (void *)"http://localhost/bps/pub/v2/login";
		}

		if (strstr(url, "/bps/pub/v2/lobby/reconnect"))
		{
			data = (void *)"http://localhost/bps/pub/v2/lobby/reconnect";
		}

		if (strstr(url, "/bps/pub/bi/session/create"))
		{
			data = (void *)"http://localhost/bps/pub/bi/session/create";
		}

		if (strstr(url, "/bps/pub/lobby"))
		{
			data = (void *)"http://localhost/bps/pub/lobby";
		}

		if (strstr(url, "/bps/pub/matchmake/request"))
		{
			data = (void *)"http://localhost/bps/pub/matchmake/request";
		}

		if (strstr(url, "/bps/pub/bi/session/event/bulk"))
		{
			data = (void *)"http://localhost/bps/pub/bi/session/event/bulk";
		}

		if (strstr(url, "/bps/pub/character/list"))
		{
			data = (void *)"http://localhost/bps/pub/character/list";
		}

		if (strstr(url, "/bps/pub/matchmake/find"))
		{
			data = (void *)"http://localhost/bps/pub/matchmake/find";
		}
	}

	// CURLOPT_SSL_VERIFYPEER
	if (option == 64)
		data = (void *)0;

	// CURLOPT_SSL_VERIFYHOST
	if (option == 81)
		data = (void *)0;

	return ((int(*)(void *, int, __int64))(g_ModuleBase + 0x18C0390))(curl, option, (__int64)&data);
}

void LogFunc1(const char *Format, ...)
{
	va_list va;
	va_start(va, Format);
	vfprintf(g_OutFile, Format, va);
	va_end(va);
}

void LogFunc2(int Type, const char *Format, ...)
{
	va_list va;
	va_start(va, Format);
	vfprintf(g_OutFile, Format, va);
	va_end(va);
}

void LogFunc4(void *a1, const char *Format, ...)
{
	va_list va;
	va_start(va, Format);
	vfprintf(g_OutFile, Format, va);
	va_end(va);
}

int LogFunc5(__int64 a1, const char *Format, ...)
{
	va_list va;
	va_start(va, Format);
	vfprintf(g_OutFile, Format, va);
	va_end(va);
	return 0;
}

__int64(*oLogFunc7)(void *, const char *);
__int64 LogFunc7(void *a1, const char *a2)
{
	fprintf(g_OutFile, "%s\n", a2);
	return oLogFunc7(a1, a2);
}

void InitServerThreads();
void CreateOpenSSLServer();

void DumpScriptCommandList()
{
	struct ParamEntry
	{
		const char *Name;
		void *Unknown;
	};

	struct CommandEntry
	{
		const char *LongName;
		const char *ShortName;
		int Id;
		const char *Description;
		uint8_t Unknown;
		uint8_t Unknown2;
		uint8_t ParamCount;
		ParamEntry *Params;
		void *UnknownFunc;
		void *ParserFunc;
		void *CommandFunc;
		char _padding[8];
	};

	static_assert(sizeof(ParamEntry) == 0x10, "");
	static_assert(sizeof(CommandEntry) == 0x50, "");

	CommandEntry *entries = (CommandEntry *)(g_ModuleBase + 0x44D41A0);

	FILE *f = fopen("C:\\commandlist.txt", "w");

	for (int i = 0; i < 891; i++)
	{
		auto *e = &entries[i];

		fprintf(f, "{ \"%s\", \"%s\", %d, \"%s\", %d, { ", e->LongName, e->ShortName, e->Id, e->Description, e->ParamCount);

		if (e->Params)
		{
			for (int j = 0; j < e->ParamCount; j++)
			{
				fprintf(f, "\"%s\", ", e->Params[j].Name);
			}
		}

		fprintf(f, "} }\n");
	}

	fflush(f);
	fclose(f);
}

bool hk___scrt_initialize_crt(void *a1, void *a2)
{
	fopen_s(&g_OutFile, "C:\\out.txt", "w");
	fopen_s(&g_CurlOutFile, "C:\\curl_out.txt", "w");

	setbuf(g_OutFile, nullptr);
	setbuf(g_CurlOutFile, nullptr);

	//DumpScriptCommandList();
	//exit(0);

	//std::thread t([]()
	//{
	//	CreateOpenSSLServer();
	//});
	//t.detach();

	//InitServerThreads();

	WriteJump(g_ModuleBase + 0x1C73670, (uintptr_t)&LogFunc1);
	WriteJump(g_ModuleBase + 0x11E5C70, (uintptr_t)&LogFunc1);
	WriteJump(g_ModuleBase + 0x1C73540, (uintptr_t)&LogFunc1);
	WriteJump(g_ModuleBase + 0x2CEBF80, (uintptr_t)&LogFunc2);
	WriteJump(g_ModuleBase + 0x165EF20, (uintptr_t)&LogFunc4);
	WriteJump(g_ModuleBase + 0x1D08FD0, (uintptr_t)&LogFunc5);
	//*(PBYTE *)&oLogFunc7 = Detours::X64::DetourFunction((PBYTE)g_ModuleBase + 0x2A5170, (PBYTE)&LogFunc7);

	WriteJump(g_ModuleBase + 0x2BB9700, (uintptr_t)&hk_sub_142B1B0A0);
	WriteJump(g_ModuleBase + 0x2BB9340, (uintptr_t)&hk_sub_142B1ACE0);
	WriteJump(g_ModuleBase + 0x2BB9540, (uintptr_t)&hk_sub_142B1AEE0);
	WriteJump(g_ModuleBase + 0x2BB9ED0, (uintptr_t)&hk_sub_142B1B870);

	PatchMemory(g_ModuleBase + 0x2BAFB7A + 0x7, (PBYTE)"\x00", 1);// Force global log level to TRACE (0)
	PatchMemory(g_ModuleBase + 0x2BB9530, (PBYTE)"\xC3", 1);// Prevent it from being set to anything but 0

	// Force pushy to succeed every time even if it's not connected
	//WriteJump(g_ModuleBase + 0x1E74070, g_ModuleBase + 0x1E73AE0);

	// Force console commands to be logged (mostly useless, console is stripped)
	//*(bool *)(*(uintptr_t *)(__readgsqword(0x58u) + 8i64 * (unsigned int)0) + 496i64) = true;

	// Kill anticheat variable for process and dll names (x64dbg.exe, ida.exe)
	PatchMemory(g_ModuleBase + 0x02E4F00, (PBYTE)"\xC3", 1);

	// Hook CURL
	//WriteJump(g_ModuleBase + 0x18C26F0, (uintptr_t)&hk_curl_easy_setopt);

	const char *ptr = "http://localhost";
	//PatchMemory(g_ModuleBase + 0x4520978, (PBYTE)&ptr, 8);
	//PatchMemory(g_ModuleBase + 0x45209B8, (PBYTE)&ptr, 8);

	return ((decltype(&hk___scrt_initialize_crt))(g_ModuleBase + 0x2BCD118))(a1, a2);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		char filePath[MAX_PATH];
		GetModuleFileNameA(GetModuleHandle(nullptr), filePath, MAX_PATH);

		if (strstr(filePath, "Fallout76.exe"))
		{
			// Hijack the pre-CRT call that runs before all static constructors
			g_ModuleBase = (uintptr_t)GetModuleHandle(nullptr);
			WriteCall(g_ModuleBase + 0x2BCDD4F, (uintptr_t)&hk___scrt_initialize_crt);
		}
	}

	return TRUE;
}
