#ifndef utils_hpp
#define utils_hpp

#include <map>
#include <memory>
#include <random>
#include <signal.h>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>

#include "ip2region/xdb_search.h"
#include "loguru.hpp"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "tsharkDataType.hpp"

// 前向声明SQLite结构体
struct sqlite3;
// 不需要前向声明Packet，因为已经包含了tsharkDataType.hpp
// class Packet;

extern std::unordered_map<std::string, std::string> translationMap;
extern std::map<std::string, std::string>           translationMap2;

class CommonUtil
{
public:
    // 获取当前时间戳
    static std::string get_timestamp();
    // 将UTF-8字符串转换为ANSI字符串
    static std::string UTF8ToANSIString(const std::string& utf8Str);
    // 翻译字段
    static void translateShowNameFields(rapidjson::Value&                   value,
                                        rapidjson::Document::AllocatorType& allocator);
    // map性能对比函数
    static void compareMapPerformance(int iterations = 10000);
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
#endif

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
};

class SQLiteUtil
{
public:
    SQLiteUtil(const std::string& dbname);
    ~SQLiteUtil();
    bool createPacketTable();
    bool insertPacket(std::vector<std::shared_ptr<Packet>>& packets);
    bool queryPacket(std::vector<std::shared_ptr<Packet>>& packetList);

private:
    sqlite3* db = nullptr;
};

#endif