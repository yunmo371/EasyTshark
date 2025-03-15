#ifndef utils_hpp
#define utils_hpp

#include <memory>
#include <random>
#include <signal.h>
#include <string>
#include <sys/types.h>
#include <unistd.h>

#include "ip2region/xdb_search.h"

class CommonUtil
{
public:
    static std::string get_timestamp();
    static std::string UTF8ToANSIString(const std::string& utf8Str);
};

class IP2RegionUtil
{
public:
    static bool        init(const std::string& xdbFilePath);
    static std::string getIpLocation(const std::string& ip);

private:
    static std::string                   parseLocation(const std::string& input);
    static std::shared_ptr<xdb_search_t> xdbPtr;
};

class ProcessUtil
{
public:
#if defined(__unix__) || defined(__APPLE__)
    static FILE* PopenEx(std::string command, pid_t* pidOut = nullptr)
    {
        int   pipefd[2] = {0};
        FILE* pipeFp    = nullptr;

        if (pipe(pipefd) == -1)
        {
            perror("pipe");
            return nullptr;
        }

        pid_t pid = fork();
        if (pid == -1)
        {
            perror("fork");
            close(pipefd[0]);
            close(pipefd[1]);
            return nullptr;
        }

        if (pid == 0)
        {
            // 子进程
            close(pipefd[0]);               // 关闭读端
            dup2(pipefd[1], STDOUT_FILENO); // 将 stdout 重定向到管道
            dup2(pipefd[1], STDERR_FILENO); // 将 stderr 重定向到管道
            close(pipefd[1]);

            execl("/bin/sh", "sh", "-c", command.c_str(), NULL); // 执行命令
            _exit(1);                                            // execl失败
        }

        // 父进程将读取管道，关闭写端
        close(pipefd[1]);
        pipeFp = fdopen(pipefd[0], "r");

        if (pidOut)
        {
            *pidOut = pid;
        }

        return pipeFp;
    }

    static int Kill(pid_t pid)
    {
        return kill(pid, SIGTERM);
    }

    static bool Exec(std::string cmdline)
    {
#ifdef _WIN32
        PROCESS_INFORMATION piProcInfo;
        STARTUPINFO         siStartInfo;

        // 初始化 STARTUPINFO 结构体
        ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
        ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));

        // 创建子进程
        if (CreateProcess(nullptr,               // No module name (use command line)
                          (LPSTR)cmdline.data(), // Command line
                          nullptr,               // Process handle not inheritable
                          nullptr,               // Thread handle not inheritable
                          TRUE,                  // Set handle inheritance
                          CREATE_NO_WINDOW,      // No window
                          nullptr,               // Use parent's environment block
                          nullptr,               // Use parent's starting directory
                          &siStartInfo,          // Pointer to STARTUPINFO structure
                          &piProcInfo            // Pointer to PROCESS_INFORMATION structure
                          ))
        {
            WaitForSingleObject(piProcInfo.hProcess, INFINITE);
            CloseHandle(piProcInfo.hProcess);
            CloseHandle(piProcInfo.hThread);
            return true;
        }
        else
        {
            return false;
        }
#else
        return std::system(cmdline.c_str()) == 0;
#endif
    }

#endif
};

#endif