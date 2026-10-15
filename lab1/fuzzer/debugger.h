#pragma once
#include <iostream>
#include <Windows.h>

class Debugger
{
public:
	Debugger();
	~Debugger();

	enum States {
		CONTINUE_DEBUG,
		EXCEPTION,
		FINISHED
	};

	BOOL loadProcess(LPCTSTR executablePath, LPTSTR arguments);
	BOOL detachProcess();
	BOOL run(std::string logfile);

	LPCONTEXT getThreadContext(DWORD threadID);
	BOOL generate_dump(DWORD threadID, HANDLE h_Process, DWORD ExceptionCode, std::string log_file);
	int hexDump(const void* addr, const int len, LPCVOID offset, char*);

	HANDLE hProcess;
	DWORD processID;
	HANDLE hThread;
	DWORD threadID;
	BOOL firstBreakpointOccured;
	DWORD pageSize;
	CONTEXT savedContext;

private:
	BOOL debugEventHandler(const DEBUG_EVENT* debugEvent, std::string log_file);
	BOOL exceptionDebugEventHandler(const DEBUG_EVENT* debugEvent, std::string log_file);
	BOOL createProcessDebugEventHandler(const DEBUG_EVENT* debugEvent);
	BOOL exitProcessDebugEventHandler(const DEBUG_EVENT* debugEvent);
};
