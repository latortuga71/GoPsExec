//go:build exclude
// NamedPipeSvc.cpp : This file contains the 'main' function. Program execution begins and ends there.
// make sure its a static build papi
// shout out @zodiacon.

#include <windows.h>
#include <stdio.h>
#include <string>
#include <atlbase.h>
#include <AclAPI.h>

/* globals */
SERVICE_STATUS_HANDLE g_hService;
SERVICE_STATUS g_Status;
HANDLE g_hStopEvent;
HANDLE g_hNamedPipe;

void SetStatus(DWORD status);

enum class MessageType {
    Command,
    Stop,
    Done
};

struct Message {
    MessageType Type;
    char Data[1024];
};

int Error(const char* msg) {
    printf("%s -> %u\n", msg, GetLastError());
    return 1;
}


DWORD WINAPI NamedPipeSvcMainHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext) {
    switch (dwControl) {
    case SERVICE_CONTROL_STOP:
        SetStatus(SERVICE_STOP_PENDING);
        SetEvent(g_hStopEvent);
        CloseHandle(g_hNamedPipe);
        break;
    }
    return 0;
}

void SetStatus(DWORD status) {
    g_Status.dwCurrentState = status;
    g_Status.dwControlsAccepted = status == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP : 0;
    SetServiceStatus(g_hService, &g_Status);
}


char* HandleCommand(char* command) {
    SECURITY_ATTRIBUTES saAttr;
    // Set the bInheritHandle flag so pipe handles are inherited. 
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;
    //https://docs.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output
    HANDLE hStdinRead, hStdinWrite;
    HANDLE hStdoutRead, hStdoutWrite;
    if (!CreatePipe(&hStdoutRead, &hStdoutWrite, &saAttr, 0))
        return NULL;
    SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);
    if (!CreatePipe(&hStdinRead, &hStdinWrite, &saAttr, 0))
        return NULL;
    SetHandleInformation(hStdinWrite, HANDLE_FLAG_INHERIT, 0);
    // create process
    PROCESS_INFORMATION pi;
    STARTUPINFOA si = { sizeof(si) };
    si.cb = sizeof(STARTUPINFOA);
    si.hStdError = hStdoutWrite;
    si.hStdOutput = hStdoutWrite;
    //si.hStdInput = hStdinRead;
    si.dwFlags |= STARTF_USESTDHANDLES;
    if (!CreateProcessA("C:\\windows\\system32\\cmd.exe", command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        printf("Create Process Error %u\n", GetLastError());
        return NULL;
    }
    CloseHandle(pi.hThread);
    CloseHandle(hStdoutWrite);
    // read from pipes once process dies.
    char text[512];
    std::string commandOutput = "";
    DWORD read;
    while (WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT) {
        if (!ReadFile(hStdoutRead, text, sizeof(text) - 1, &read, NULL)) {
            break;
        }
        text[read] = 0;
        commandOutput += text;
    }
    CloseHandle(hStdoutRead);
    CloseHandle(pi.hProcess);
    char* out = (char*)VirtualAlloc(NULL, commandOutput.size() - 1, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(GetCurrentProcess(), out, commandOutput.c_str(), commandOutput.size() - 1, NULL);
    return out;
}


void HandleResponse(char* commandOutput) {
    BOOL success;
    DWORD nWrote;
    char* commandOutputStart = commandOutput;
    int bytesLeftToSend = strlen(commandOutput);
    Message response = {};
    response.Type = MessageType::Command;
    while (bytesLeftToSend != 0) {
        if (commandOutput != NULL) {
            if (strlen(commandOutput) < 1024) {
                strncpy_s(response.Data, commandOutput, strlen(commandOutput));
                bytesLeftToSend = 0;
                response.Type = MessageType::Done;
            }
            else {
                strncpy_s(response.Data, commandOutput, 1023);
                commandOutput += 1023;
                bytesLeftToSend -= 1023;
            }
        }
        else {
            strncpy_s(response.Data, "Command Failed!", 15);
            response.Type = MessageType::Done;
            bytesLeftToSend = 0;
        }

        success = WriteFile(g_hNamedPipe, &response, sizeof(response), &nWrote, NULL);
        if (!success || nWrote != sizeof(response)) {
            break;
        }
    }
}




void WINAPI NamedPipeSvcMain(DWORD dwNumServicesArgs, LPTSTR* args) {
    g_Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_Status.dwWaitHint = 500;
    bool error = true;
    // named pipe setup and service init
    do {
        g_hService = RegisterServiceCtrlHandlerEx(L"GoExec", NamedPipeSvcMainHandler, NULL);
        if (!g_hService)
            break;
        g_hStopEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (!g_hStopEvent)
            break;
        SetStatus(SERVICE_START_PENDING);
        g_hNamedPipe = CreateNamedPipeW(L"\\\\.\\pipe\\slotty", PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES, sizeof(Message), sizeof(Message), 0, NULL);
        if (g_hNamedPipe == INVALID_HANDLE_VALUE)
            break; 
        SetStatus(SERVICE_RUNNING);
        error = false;
    } while (false);
    if (error) {
        SetStatus(SERVICE_STOPPED);
        return;
    }
    // service is now running. lets handle messages from named pipe
    BOOL success;
    DWORD nRead;
    Message msg = {};
    while (WaitForSingleObject(g_hStopEvent, 1000) == WAIT_TIMEOUT) {
        if (!ConnectNamedPipe(g_hNamedPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED)
            break;
        //client is connected now lets read until we get a command
        success = ReadFile(g_hNamedPipe, &msg, sizeof(msg), &nRead, NULL);
        if (!success || nRead == 0) {
            if (GetLastError() == ERROR_BROKEN_PIPE)
                printf("Client Disconnected\n");
            else
                printf("Read From Pipe Failed %u", GetLastError());
            break;
        }
        switch (msg.Type) {
        case MessageType::Stop:
            SetEvent(g_hStopEvent);
            FlushFileBuffers(g_hNamedPipe);
            DisconnectNamedPipe(g_hNamedPipe);
            break;
        case MessageType::Command:
            char* commandOutput = HandleCommand(msg.Data);
            HandleResponse(commandOutput);
            FlushFileBuffers(g_hNamedPipe);
            DisconnectNamedPipe(g_hNamedPipe);
            break;
        }
    }
    SetStatus(SERVICE_STOPPED);
    CloseHandle(g_hStopEvent);
    CloseHandle(g_hNamedPipe);
}
int main()
{
    WCHAR name[] = L"GoPsExec";
    const SERVICE_TABLE_ENTRY table[] = { { name, NamedPipeSvcMain }, { NULL,NULL } };
    if (!StartServiceCtrlDispatcherW(table)) {
        return 1;
    }
    return 0;
}