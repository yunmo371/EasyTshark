#include <array>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <thread>

#include "loguru.hpp"
#include "tsharkManager.hpp"
#include "utils.hpp"


int main(int argc, char* argv[])
{
    // 初始化日志
    std::string ts               = CommonUtil::get_timestamp();
    std::string capture_log_name = "logs/catch_log_" + ts + ".txt";
    loguru::init(argc, argv);
    loguru::add_file(capture_log_name.c_str(), loguru::Append, loguru::Verbosity_MAX);

    // 清空data目录
    std::string dataDir = "data";
    std::string rmCmd = "rm -rf " + dataDir + "/*";
    std::system(rmCmd.c_str());
    std::cout << "已清空data目录" << std::endl;

    // 创建data目录（如果不存在）
    std::string mkdirCmd = "mkdir -p " + dataDir;
    std::system(mkdirCmd.c_str());

    // 创建TsharkManager实例
    TsharkManager tsharkManager("/root/dev/learn_from_xuanyuan/output");

    // 获取网卡列表
    std::vector<AdapterInfo> adapters = tsharkManager.getNetworkAdapterInfo();
    std::cout << "可用网卡列表：" << std::endl;
    for (const auto& adapter : adapters)
    {
        std::cout << adapter.id << ": " << adapter.name << " (" << adapter.remark << ")"
                  << std::endl;
    }

    // 用户选择网卡
    std::string adapterName;
    std::cout << "请输入要监控的网卡名称: ";
    std::cin >> adapterName;

    // 用户输入抓包时间
    int captureSeconds;
    std::cout << "请输入抓包时间(秒): ";
    std::cin >> captureSeconds;

    // 开始抓包
    std::cout << "开始抓包，持续 " << captureSeconds << " 秒..." << std::endl;
    tsharkManager.startCapture(adapterName);

    // 等待指定的秒数
    std::this_thread::sleep_for(std::chrono::seconds(captureSeconds));

    // 停止抓包
    tsharkManager.stopCapture();
    
    // 将capture.pcap移动到data目录
    std::string pcapFile = "capture.pcap";
    std::string dataPcapFile = dataDir + "/capture.pcap";
    std::string mvCmd = "mv " + pcapFile + " " + dataPcapFile;
    std::system(mvCmd.c_str());
    std::cout << "抓包已完成，保存到 " << dataPcapFile << std::endl;

    // 将PCAP文件转换为XML
    std::string xmlFile  = dataDir + "/packets.xml";
    if (tsharkManager.convertPcapToXml(dataPcapFile, xmlFile))
    {
        std::cout << "PCAP文件已成功转换为XML文件: " << xmlFile << std::endl;

        // 将XML文件转换为JSON
        std::string jsonFile = dataDir + "/packets.json";
        if (tsharkManager.convertXmlToJson(xmlFile, jsonFile))
        {
            std::cout << "处理完成！" << std::endl;
        }
        else
        {
            std::cerr << "XML转JSON失败" << std::endl;
        }
    }
    else
    {
        std::cerr << "PCAP转XML失败" << std::endl;
    }

    // 执行map和unordered_map性能对比
    CommonUtil::compareMapPerformance(10000);

    return 0;
}
