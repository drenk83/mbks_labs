#include "debugger.h"
#include <iostream>
#include <fstream>

#define OUTPUT_MSG_SIZE 1000

Debugger::Debugger() {
	this->hProcess = NULL;
	this->processID = NULL;
	this->hThread = NULL;
	this->threadID = NULL;
	this->firstBreakpointOccured = FALSE;
	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);
	this->pageSize = systemInfo.dwPageSize;
}

Debugger::~Debugger() {
	this->detachProcess();
}

BOOL Debugger::loadProcess(LPCTSTR executablePath, LPTSTR arguments) {
	STARTUPINFO startupInfo;
	ZeroMemory(&startupInfo, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);
	startupInfo.dwFlags = STARTF_USESHOWWINDOW;
	startupInfo.wShowWindow = SW_HIDE;

	PROCESS_INFORMATION processInformation;

	WCHAR workDir[MAX_PATH];
	wcscpy_s(workDir, MAX_PATH, executablePath);
	WCHAR* slash = wcsrchr(workDir, L'\\');
	if (slash != NULL) {
		*slash = L'\0';
	}

	if (CreateProcess(executablePath, arguments, NULL, NULL, NULL,
		DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED | CREATE_NO_WINDOW,
		NULL, workDir, &startupInfo, &processInformation)) {
		this->hProcess = processInformation.hProcess;
		this->processID = processInformation.dwProcessId;
		this->hThread = processInformation.hThread;
		this->threadID = processInformation.dwThreadId;
		return TRUE;
	}
	{
		DWORD error = GetLastError();
		std::cerr << "CreateProcess failed with error code: " << error << std::endl;
	}
	return FALSE;
}

BOOL Debugger::detachProcess() {
	DebugActiveProcessStop(this->processID);
	return TRUE;
}

BOOL Debugger::run(std::string log_file) {
	DEBUG_EVENT debugEvent;
	ResumeThread(this->hThread);
	while (WaitForDebugEvent(&debugEvent, INFINITE))
	{
		int status = this->debugEventHandler(&debugEvent, log_file);
		if (status == CONTINUE_DEBUG)
		{
			ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
		}
		else if (status == EXCEPTION)
		{
			return FALSE;
		}
		else if (status == FINISHED) {
			return TRUE;
		}
	}
	return TRUE;
}

BOOL Debugger::debugEventHandler(const DEBUG_EVENT* debugEvent, std::string log_file)
{
	switch (debugEvent->dwDebugEventCode)
	{
	case CREATE_PROCESS_DEBUG_EVENT:
		return this->createProcessDebugEventHandler(debugEvent);

	case EXCEPTION_DEBUG_EVENT:
		return this->exceptionDebugEventHandler(debugEvent, log_file);

	case EXIT_PROCESS_DEBUG_EVENT:
		return this->exitProcessDebugEventHandler(debugEvent);

	default:
		return CONTINUE_DEBUG;
	}
	return true;
}

BOOL Debugger::exceptionDebugEventHandler(const DEBUG_EVENT* debugEvent, std::string log_file)
{
	switch (debugEvent->u.Exception.ExceptionRecord.ExceptionCode)
	{
	case EXCEPTION_BREAKPOINT:
		return CONTINUE_DEBUG;
	case EXCEPTION_SINGLE_STEP:
		return CONTINUE_DEBUG;
	default:
		generate_dump(debugEvent->dwThreadId, this->hProcess, debugEvent->u.Exception.ExceptionRecord.ExceptionCode, log_file);
		return EXCEPTION;
	}

}

BOOL Debugger::createProcessDebugEventHandler(const DEBUG_EVENT* debugEvent)
{
	return CONTINUE_DEBUG;
}

BOOL Debugger::exitProcessDebugEventHandler(const DEBUG_EVENT* debugEvent)
{
	return FINISHED;
}

LPCONTEXT Debugger::getThreadContext(DWORD threadID)
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadID);

	this->savedContext.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

	if (hThread != 0) {
		if (GetThreadContext(hThread, &this->savedContext))
		{
			CloseHandle(hThread);
			return &this->savedContext;
		}
		else
		{
			return NULL;
		}
	}
	else {
		return NULL;
	}
}

BOOL Debugger::generate_dump(DWORD threadID, HANDLE h_Process, DWORD ExceptionCode, std::string log_file)
{
	LPCONTEXT threadContext = this->getThreadContext(threadID);
	char buffer[256] = { 0 };
	SIZE_T recvSize = 0;
	char output_message[OUTPUT_MSG_SIZE] = { 0 };

	std::ofstream out(log_file);
	if (!out.is_open())
	{
		return FALSE;
	}

	snprintf(output_message, 1000, "Program crashed.\n Exception code: %X\n\nRegisters:\nEax: 0x%X\nEip: 0x%X\nEbp: 0x%X\nEcx: 0x%X\nEdx: 0x%X\nEdi: 0x%X\nEsi: 0x%X\nEsp: 0x%X\n\n", ExceptionCode, threadContext->Eax, threadContext->Eip, threadContext->Ebp, threadContext->Ecx, threadContext->Edx, threadContext->Edi, threadContext->Esi, threadContext->Esp);
	out << output_message;

	DWORD esp = threadContext->Esp;
	if (ReadProcessMemory(h_Process, (LPCVOID)esp, buffer, sizeof(buffer), &recvSize) != 0) {
		snprintf(output_message, 1000, "Stack (%d) bytes read:", recvSize);
		out << output_message;

		int writed = hexDump(buffer, recvSize, (LPCVOID)esp, output_message);
		out.write(output_message, writed);
	}
	else {
		out << "The Esp register has been corrupted, data cannot be read!\n";
	}
	out.close();
	return TRUE;
}

int Debugger::hexDump(const void* addr, const int len, LPCVOID offset, char* output_message) {
	int writed = 0;
	const int perLine = 16;
	int i;
	unsigned char buff[perLine + 1];
	const unsigned char* pc = (const unsigned char*)addr;
	if (len == 0) {
		writed += snprintf(output_message + writed, OUTPUT_MSG_SIZE - writed, "  ZERO LENGTH\n");
		//printf("  ZERO LENGTH\n");
		return writed;
	}
	if (len < 0) {
		writed += snprintf(output_message + writed, OUTPUT_MSG_SIZE - writed, "  NEGATIVE LENGTH: %d\n", len);
		return writed;
	}

	// Process every byte in the data.

	for (i = 0; i < len; i++) {
		// Multiple of perLine means new or first line (with line offset).

		if ((i % perLine) == 0) {
			// Only print previous-line ASCII buffer for lines beyond first.

			if (i != 0) {
				writed += snprintf(output_message + writed, OUTPUT_MSG_SIZE - writed, "  %s\n", buff);
			}

			// Output the offset of current line.
			writed += snprintf(output_message + writed, OUTPUT_MSG_SIZE - writed, "0x%04x ", i + (int)offset);
		}

		// Now the hex code for the specific character.
		writed += snprintf(output_message + writed, OUTPUT_MSG_SIZE - writed, " %02x", pc[i]);

		// And buffer a printable ASCII character for later.

		if ((pc[i] < 0x20) || (pc[i] > 0x7e)) // isprint() may be better.
			buff[i % perLine] = '.';
		else
			buff[i % perLine] = pc[i];
		buff[(i % perLine) + 1] = '\0';
	}

	// Pad out last line if not exactly perLine characters.

	while ((i % perLine) != 0) {
		writed += snprintf(output_message + writed, OUTPUT_MSG_SIZE - writed, "   ");
		i++;
	}

	// And print the final ASCII buffer.
	writed += snprintf(output_message + writed, OUTPUT_MSG_SIZE - writed, "  %s\n", buff);
	return writed;
}