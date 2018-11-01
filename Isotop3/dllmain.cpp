#include <windows.h>
#include <stdio.h>
#include <mutex>
#include "util.h"

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
	}

	// CURLOPT_SSL_VERIFYPEER
	if (option == 64)
		data = (void *)0;

	// CURLOPT_SSL_VERIFYHOST
	if (option == 81)
		data = (void *)0;

	return ((int(*)(void *, int, __int64))(g_ModuleBase + 0x18232D0))(curl, option, (__int64)&data);
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

__int64(*oLogFunc7)(void *, const char *);
__int64 LogFunc7(void *a1, const char *a2)
{
	fprintf(g_OutFile, "%s\n", a2);
	return oLogFunc7(a1, a2);
}

bool hk___scrt_initialize_crt(void *a1, void *a2)
{
	fopen_s(&g_OutFile, "C:\\out.txt", "w");
	fopen_s(&g_CurlOutFile, "C:\\curl_out.txt", "w");

	setbuf(g_OutFile, nullptr);
	setbuf(g_CurlOutFile, nullptr);

	WriteJump(g_ModuleBase + 0x1BD6590, (uintptr_t)&LogFunc1);
	WriteJump(g_ModuleBase + 0x11490C0, (uintptr_t)&LogFunc1);
	WriteJump(g_ModuleBase + 0x1BD6460, (uintptr_t)&LogFunc1);
	WriteJump(g_ModuleBase + 0x2C4D6C0, (uintptr_t)&LogFunc2);
	WriteJump(g_ModuleBase + 0x15C2CD0, (uintptr_t)&LogFunc4);
	//*(PBYTE *)&oLogFunc7 = Detours::X64::DetourFunction((PBYTE)g_ModuleBase + 0x214010, (PBYTE)&LogFunc7);

	WriteJump(g_ModuleBase + 0x1825630, (uintptr_t)&hk_curl_easy_setopt);

	PatchMemory(g_ModuleBase + 0x2B11521, (PBYTE)"\x00", 1);// Force global log level to TRACE (0)
	PatchMemory(g_ModuleBase + 0x2B1AED0, (PBYTE)"\xC3", 1);// Prevent it from being set to anything but 0

	WriteJump(g_ModuleBase + 0x2B1B0A0, (uintptr_t)&hk_sub_142B1B0A0);
	WriteJump(g_ModuleBase + 0x2B1ACE0, (uintptr_t)&hk_sub_142B1ACE0);
	WriteJump(g_ModuleBase + 0x2B1AEE0, (uintptr_t)&hk_sub_142B1AEE0);
	PatchMemory(g_ModuleBase + 0x2B1B870, (PBYTE)"\xC3", 1);// Crash related to custom hk_sub_142B1B0A0/hk_sub_142B1AEE0 (has more information)

	PatchMemory(g_ModuleBase + 0xC94570, (PBYTE)"\x90\x90\x90\x90\x90\x90", 6);// Force main menu even if login fails
	PatchMemory(g_ModuleBase + 0xCA330D, (PBYTE)"\x90\x90\x90\x90\x90\x90", 6);// Force main menu even if login fails

	// Force console commands to be logged (mostly useless, console is stripped)
	//*(bool *)(*(uintptr_t *)(__readgsqword(0x58u) + 8i64 * (unsigned int)0) + 496i64) = true;

	// Kill anticheat variable for process and dll names (x64dbg.exe, ida.exe)
	PatchMemory(g_ModuleBase + 0x253200, (PBYTE)"\xC3", 1);

	return ((decltype(&hk___scrt_initialize_crt))(g_ModuleBase + 0x2B2EAD8))(a1, a2);
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
			WriteCall(g_ModuleBase + 0x2B2F70F, (uintptr_t)&hk___scrt_initialize_crt);
		}
	}

	return TRUE;
}
