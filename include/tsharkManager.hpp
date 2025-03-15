#ifndef tsharkManager_hpp
#define tsharkManager_hpp

#include "rapidjson/document.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "rapidxml/rapidxml.hpp"
#include "rapidxml/rapidxml_utils.hpp"
#include "tsharkDataType.hpp"
#include "utils.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <random>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace rapidxml;
using namespace rapidjson;

class AdapterMonitorInfo
{
public:
    AdapterMonitorInfo()
    {
        monitorTsharkPipe = nullptr;
        tsharkPid         = 0;
    }
    std::string                  adapterName;       // 网卡名称
    std::map<long, long>         flowTrendData;     // 流量趋势数据
    std::shared_ptr<std::thread> monitorThread;     // 负责监控该网卡输出的线程
    FILE*                        monitorTsharkPipe; // 线程与tshark通信的管道
    pid_t                        tsharkPid;         // 负责捕获该网卡数据的tshark进程PID
};

class TsharkManager
{
public:
    TsharkManager(std::string currentFilePath);
    ~TsharkManager();

    // 分析数据包文件
    bool analysisFile(std::string filePath);

    // 分析数据包文件并返回数据包列表
    bool analysisFile(std::string filePath, std::vector<std::shared_ptr<Packet>>& packets);

    // 打印所有数据包的信息
    void printAllPackets();

    // 获取指定编号数据包的十六进制数据
    bool getPacketHexData(uint32_t frameNumber, std::vector<unsigned char>& data);

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
    void getAdaptersFlowTrendData(std::map<std::string, std::map<long, long>>& flowTrendData);

    // 获取tshark路径
    std::string getTsharkPath() const
    {
        return tsharkPath;
    }

    // 将PCAP文件转换为XML格式
    bool convertPcapToXml(const std::string& pcapFile, const std::string& xmlFile);

    // 将XML文件转换为JSON文件
    bool convertXmlToJson(const std::string& xmlFile, const std::string& jsonFile);

private:
    // 辅助函数：将XML节点转换为JSON节点
    void convertXmlNodeToJson(rapidxml::xml_node<>* xmlNode, rapidjson::Value& jsonNode,
                              rapidjson::Document::AllocatorType& allocator);

    // 解析行数据
    bool parseLine(std::string line, std::shared_ptr<Packet> packet);

    // 存储线程
    void storageThreadEntry();

    // 处理每一个数据包
    void processPacket(std::shared_ptr<Packet> packet);

private:
    // 等待存储入库的数据
    std::vector<std::shared_ptr<Packet>> waitInsertPackets;

    // 访问待存储数据的锁
    std::mutex waitInsertPacketsLock;

    // 存储线程，负责将获取到的数据包和会话信息存储入库中
    std::shared_ptr<std::thread> storageThread;

    // 数据库存储
    std::shared_ptr<SQLiteUtil> sqliteUtil;

    // tshark路径
    std::string tsharkPath;

    // editcap路径
    std::string editcapPath;

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

class MiscUtil
{
public:
    // 获得随机字符串
    static std::string getRandomString(size_t length)
    {
        const std::string chars = "abcdefghijklmnopqrstuvwxyz"
                                  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                  "0123456789";
        std::random_device              rd;              // 用于种子
        std::mt19937                    generator(rd()); // 生成器
        std::uniform_int_distribution<> distribution(0, chars.size() - 1);

        std::string randomString;
        for (size_t i = 0; i < length; ++i)
        {
            randomString += chars[distribution(generator)];
        }

        return randomString;
    }

    static std::string getDefaultDataDir()
    {
        return "/home/";
    }

private:
    // 递归解析XML节点
    static void xml_to_json_recursive(rapidjson::Value& json, rapidxml::xml_node<>* node,
                                      rapidjson::Document::AllocatorType& allocator)
    {
        for (xml_node<>* cur_node = node->first_node(); cur_node;
             cur_node             = cur_node->next_sibling())
        {

            // 检查是否需要跳过节点
            xml_attribute<>* hide_attr = cur_node->first_attribute("hide");
            if (hide_attr && std::string(hide_attr->value()) == "yes")
            {
                continue; // 如果 hide 属性值为 "true"，跳过该节点
            }

            // 检查是否已经有该节点名称的数组
            Value* array = nullptr;
            if (json.HasMember(cur_node->name()))
            {
                array = &json[cur_node->name()];
            }
            else
            {
                Value node_array(kArrayType); // 创建新的数组
                json.AddMember(Value(cur_node->name(), allocator).Move(), node_array, allocator);
                array = &json[cur_node->name()];
            }

            // 创建一个 JSON 对象代表当前节点
            Value child_json(kObjectType);

            // 处理节点的属性
            for (xml_attribute<>* attr = cur_node->first_attribute(); attr;
                 attr                  = attr->next_attribute())
            {
                Value attr_name(attr->name(), allocator);
                Value attr_value(attr->value(), allocator);
                child_json.AddMember(attr_name, attr_value, allocator);
            }

            // 递归处理子节点
            xml_to_json_recursive(child_json, cur_node, allocator);

            // 将当前节点对象添加到对应数组中
            array->PushBack(child_json, allocator);
        }
    }
};
#endif