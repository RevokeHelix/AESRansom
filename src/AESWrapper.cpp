#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <ctime>
#include <cstdlib>
#include <sstream>
#include <iomanip>
#include <windows.h>     // For CreateProcessW, etc.

namespace fs = std::filesystem;

// =============================
// 1) CONFIGURATION
// =============================

static const std::string CONTROL_FOLDER_PATH = R"(C:\EncControl)";
static const std::string LOG_FILE_PATH = CONTROL_FOLDER_PATH + R"(\encrypt_service.log)";
static const std::string DEFAULT_KEY = "2b7e151628aed2a6abf7158809cf4f3c";

// Adjust to the actual location of AES.exe on your system:
static const std::string AES_EXE_PATH = R"(C:\EncControl\AES.exe)";

static const int CHECK_INTERVAL_SECONDS = 3;


// =============================
// 2) LOGGING & HELPERS
// =============================

void write_log(const std::string& message)
{
    try
    {
        std::ofstream logFile(LOG_FILE_PATH, std::ios::app);
        if (logFile.is_open())
        {
            logFile << "[Epoch " << std::time(nullptr) << "] " << message << "\n";
        }
    }
    catch (...) {}
}

std::string trim(const std::string& input)
{
    if (input.empty()) return input;
    const char* whitespace = " \t\r\n";
    std::size_t start = input.find_first_not_of(whitespace);
    if (start == std::string::npos) return "";
    std::size_t end = input.find_last_not_of(whitespace);
    return input.substr(start, end - start + 1);
}

std::string read_file(const fs::path& filePath)
{
    if (!fs::exists(filePath)) return "";
    try
    {
        std::ifstream inFile(filePath, std::ios::binary);
        if (!inFile.is_open()) {
            write_log("Failed to open file: " + filePath.string());
            return "";
        }
        std::ostringstream buf;
        buf << inFile.rdbuf();
        return buf.str();
    }
    catch (const std::exception& e) { write_log(std::string("Exception in read_file: ") + e.what()); }
    catch (...) { write_log("Unknown exception in read_file()"); }
    return "";
}

/**
 * Runs a command synchronously using CreateProcessW.
 * Returns the process exit code (0 means success).
 */
DWORD run_process_synchronously(const std::wstring& cmdLine)
{
    write_log("Launching process: " + std::string(cmdLine.begin(), cmdLine.end()));

    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = { 0 };

    std::wstring cmdLineMutable = cmdLine;

    if (!CreateProcessW(nullptr, &cmdLineMutable[0], nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi))
    {
        DWORD err = GetLastError();
        write_log("CreateProcessW failed. Error=" + std::to_string(err));
        return (DWORD)-1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 9999;
    if (!GetExitCodeProcess(pi.hProcess, &exitCode)) {
        DWORD err = GetLastError();
        write_log("GetExitCodeProcess failed. Error=" + std::to_string(err));
        exitCode = (DWORD)-1;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    write_log("Process exit code = " + std::to_string(exitCode));
    return exitCode;
}

// =============================
// 3) ENCRYPTION / DECRYPTION
// =============================

/**
 * Encrypts a file using AES.
 */
void encrypt_file(const fs::path& file_path)
{
    if (!fs::exists(file_path))
    {
        write_log("ERROR: File does not exist: " + file_path.string());
        return;
    }

    fs::path encrypted_file = file_path;
    encrypted_file += ".enc";

    std::wstring cmdLine =
        L"\"" + fs::path(AES_EXE_PATH).wstring() + L"\""
        L" encrypt "
        L"\"" + file_path.wstring() + L"\" "
        L"\"" + encrypted_file.wstring() + L"\" "
        + std::wstring(DEFAULT_KEY.begin(), DEFAULT_KEY.end());

    DWORD exitCode = run_process_synchronously(cmdLine);

    if (exitCode == 0 && fs::exists(encrypted_file))
    {
        fs::remove(file_path);
        write_log("Deleted original file: " + file_path.string());
    }
    else
    {
        write_log("Encryption FAILED: " + file_path.string() + " (Exit Code: " + std::to_string(exitCode) + ")");
    }
}

/**
 * Decrypts a file using AES.
 */
void decrypt_file(const fs::path& file_path)
{
    if (!fs::exists(file_path))
    {
        write_log("ERROR: Encrypted file does not exist: " + file_path.string());
        return;
    }

    fs::path decrypted_file = file_path;
    decrypted_file.replace_extension(""); // Remove ".enc" extension

    std::wstring cmdLine =
        L"\"" + fs::path(AES_EXE_PATH).wstring() + L"\""
        L" decrypt "
        L"\"" + file_path.wstring() + L"\" "
        L"\"" + decrypted_file.wstring() + L"\" "
        + std::wstring(DEFAULT_KEY.begin(), DEFAULT_KEY.end());

    DWORD exitCode = run_process_synchronously(cmdLine);

    if (exitCode == 0 && fs::exists(decrypted_file))
    {
        fs::remove(file_path);
        write_log("Deleted encrypted file: " + file_path.string());
    }
    else
    {
        write_log("Decryption FAILED: " + file_path.string() + " (Exit Code: " + std::to_string(exitCode) + ")");
    }
}

/**
 * Recursively encrypts all valid files in a directory.
 */
void encrypt_directory(const fs::path& directory)
{
    write_log("Starting encryption in: " + directory.string());

    if (!fs::exists(directory) || !fs::is_directory(directory))
    {
        write_log("Invalid directory: " + directory.string());
        return;
    }

    for (const auto& entry : fs::recursive_directory_iterator(directory, fs::directory_options::skip_permission_denied))
    {
        if (!fs::is_regular_file(entry)) continue;

        const fs::path& path = entry.path();
        if (path.extension() == ".enc") continue;

        encrypt_file(path);
    }

    write_log("Finished encryption for directory: " + directory.string());
}

/**
 * Recursively decrypts all ".enc" files in a directory.
 */
void decrypt_directory(const fs::path& directory)
{
    write_log("Starting decryption in: " + directory.string());

    if (!fs::exists(directory) || !fs::is_directory(directory))
    {
        write_log("Invalid directory: " + directory.string());
        return;
    }

    for (const auto& entry : fs::recursive_directory_iterator(directory, fs::directory_options::skip_permission_denied))
    {
        if (!fs::is_regular_file(entry)) continue;

        const fs::path& path = entry.path();
        if (path.extension() != ".enc") continue;

        decrypt_file(path);
    }

    write_log("Finished decryption for directory: " + directory.string());
}

// =============================
// 4) MAIN LOOP
// =============================

int main()
{
    write_log("=== Encryption service started ===");

    while (true)
    {
        fs::path instructionPath = fs::path(CONTROL_FOLDER_PATH) / "instruction.txt";
        std::string instruction = trim(read_file(instructionPath));

        fs::path targetPathFile = fs::path(CONTROL_FOLDER_PATH) / "target_dir.txt";
        std::string targetDir = trim(read_file(targetPathFile));

        if (instruction == "ENCRYPT" && !targetDir.empty() && fs::exists(targetDir))
        {
            write_log("Received ENCRYPT instruction.");
            encrypt_directory(targetDir);
        }
        else if (instruction == "DECRYPT" && !targetDir.empty() && fs::exists(targetDir))
        {
            write_log("Received DECRYPT instruction.");
            decrypt_directory(targetDir);
        }

        std::this_thread::sleep_for(std::chrono::seconds(CHECK_INTERVAL_SECONDS));
    }

    return 0;
}
