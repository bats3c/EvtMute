#pragma once
#include <tdh.h>

#define PIPE_NAME "EvtMuteHook_Rule_Pipe"
#define RULE_BLOCK_ALL "rule Block { condition: true }"
#define RULE_ALLOW_ALL "rule Allow { condition: false }"
#define RULE_PIPE_NAME "\\\\.\\pipe\\EvtMuteHook_Rule_Pipe"

#define YRInitalize yr_initialize
#define YRFinalize yr_finalize
#define YRCompilerCreate yr_compiler_create
#define YRCompilerAddString yr_compiler_add_string
#define YRCompilerGetRules yr_compiler_get_rules
#define YRCompilerDestroy yr_compiler_destroy
#define YRRulesDestroy yr_rules_destroy
#define YRRulesScanMem yr_rules_scan_mem

VOID DoOriginalCallback(EVENT_RECORD *EventRecord);
VOID WINAPI EtwCallbackHook(EVENT_RECORD *EventRecord);
typedef VOID(WINAPI * EtwEventCallback_) (EVENT_RECORD *EventRecord);

YR_RULES*    yrRules = NULL;
YR_COMPILER* yrCompiler = NULL;

extern "C" {
	BOOL WINAPI EnumProcessModules(
		HANDLE hProcess,
		HMODULE *lphModule,
		DWORD cb,
		LPDWORD lpcbNeeded
	);
}

extern "C"
{
	DWORD
		WINAPI
		GetModuleBaseNameA(
			_In_ HANDLE hProcess,
			_In_opt_ HMODULE hModule,
			_Out_writes_(nSize) LPSTR lpBaseName,
			_In_ DWORD nSize
		); }