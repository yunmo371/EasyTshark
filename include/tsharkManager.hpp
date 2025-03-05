#ifndef tsharkManager_hpp
#define tsharkManager_hpp

#include "tsharkDataType.hpp"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <sstream>
#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <map>
#include <signal.h>

class AdapterMonitorInfo
{
public:
    AdapterMonitorInfo()
    {
        monitorTsharkPipe = nullptr;
        tsharkPid = 0;
    }
    std::string adapterName;                    // 网卡名称
    std::map<long, long> flowTrendData;         // 流量趋势数据
    std::shared_ptr<std::thread> monitorThread; // 负责监控该网卡输出的线程
    FILE *monitorTsharkPipe;                    // 线程与tshark通信的管道
    pid_t tsharkPid;                            // 负责捕获该网卡数据的tshark进程PID
};

class TsharkManager
{
public:
    TsharkManager(std::string currentFilePath);
    ~TsharkManager();

    // 分析数据包文件
    bool analysisFile(std::string filePath);

    // 打印所有数据包的信息
    void printAllPackets();

    // 获取指定编号数据包的十六进制数据
    bool getPacketHexData(uint32_t frameNumber, std::vector<unsigned char> &data);

    // 枚举网卡列表
    std::vector<AdapterInfo> getNetworkAdapterInfo();

    // 开始抓包
    bool startCapture(std::string adapterName);

    // 停止抓包
    bool stopCapture();

    // 监控所有网卡流量统计数据
    void startMonitorAdaptersFlowTrend();

    // 监控所有网卡流量趋势
    void adapterFlowTrendMonitorThreadEntry();

    // 停止监控所有网卡流量统计数据
    void stopMonitorAdaptersFlowTrend();

    // 获取所有网卡流量统计数据
    void getAdaptersFlowTrendData(std::map<std::string, std::map<long, long>> &flowTrendData);

private:
    bool parseLine(std::string line, std::shared_ptr<Packet> packet);

private:
    // 执行程序路径
    std::string tsharkPath;

    // 网卡信息
    std::vector<AdapterInfo> networkAdapters;

    // 当前分析的文件路径
    std::string currentFilePath;

    // 分析得到的所有数据包信息，key是数据包ID，value是数据包信息指针，方便根据编号获取指定数据包信息
    std::unordered_map<uint32_t, std::shared_ptr<Packet>> allPackets;

    // 在线采集数据包的工作线程
    void captureWorkThreadEntry(std::string adapterName);

    // 在线分析线程
    std::shared_ptr<std::thread> captureWorkThread;

    // 是否停止抓包的标记
    bool stopFlag;

    // 后台流量趋势监控信息
    std::map<std::string, AdapterMonitorInfo> adapterFlowTrendMonitorMap;

    // 访问上面流量趋势数据的锁
    std::recursive_mutex adapterFlowTrendMapLock;

    // epoll文件描述符
    int epollFd;

    // 网卡流量监控的开始时间
    long adapterFlowTrendMonitorStartTime = 0;
};

class ProcessUtil
{
public:
#if defined(__unix__) || defined(__APPLE__)
    static FILE *PopenEx(std::string command, pid_t *pidOut = nullptr)
    {
        int pipefd[2] = {0};
        FILE *pipeFp = nullptr;

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
};
#endif