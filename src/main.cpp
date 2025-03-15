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

    // 清空data目录 & 创建data目录
    std::string dataDir = "data";
    std::string rmCmd = "rm -rf " + dataDir + "/*";
    std::system(rmCmd.c_str());
    std::string mkdirCmd = "mkdir -p " + dataDir;
    std::system(mkdirCmd.c_str());

    // 创建TsharkManager实例
    TsharkManager tsharkManager("/root/dev/learn_from_xuanyuan/output");

    int mode;
    std::cout << "请选择模式：\n1. 实时抓包\n2. 离线分析\n请输入选择 (1或2): ";
    std::cin >> mode;

    std::string dataPcapFile = dataDir + "/capture.pcap";
    
    if (mode == 1) {
        // 抓包模式
        std::vector<AdapterInfo> adapters = tsharkManager.getNetworkAdapterInfo();
        std::cout << "可用网卡列表：" << std::endl;
        for (const auto& adapter : adapters)
        {
            std::cout << adapter.id << ": " << adapter.name << " (" << adapter.remark << ")"
                    << std::endl;
        }

        // 选择网卡
        std::string adapterName;
        std::cout << "请输入要监控的网卡名称: ";
        std::cin >> adapterName;

        // 输入抓包时间
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
        
        std::string pcapFile = "capture.pcap";
        std::string mvCmd = "mv " + pcapFile + " " + dataPcapFile;
        std::system(mvCmd.c_str());
        std::cout << "抓包已完成，保存到 " << dataPcapFile << std::endl;
    } else if (mode == 2) {
        // 离线分析模式
        std::string pcapFilePath;
        std::cout << "请输入PCAP文件路径: ";
        std::cin >> pcapFilePath;
        
        // 复制文件到data目录
        std::string cpCmd = "cp " + pcapFilePath + " " + dataPcapFile;
        if (std::system(cpCmd.c_str()) != 0) {
            std::cerr << "复制文件失败，请检查文件路径是否正确" << std::endl;
            return 1;
        }
        std::cout << "文件已复制到 " << dataPcapFile << std::endl;
    } else {
        std::cerr << "无效的选择，程序退出" << std::endl;
        return 1;
    }

    // 创建SQLite数据库并导入数据包
    std::string dbPath = dataDir + "/packets.db";
    SQLiteUtil sqliteUtil(dbPath);
    
    // 创建数据表
    if (sqliteUtil.createPacketTable()) {
        std::cout << "成功创建数据表" << std::endl;
        
        // 解析PCAP文件
        std::vector<std::shared_ptr<Packet>> packets;
        if (tsharkManager.analysisFile(dataPcapFile, packets)) {
            std::cout << "成功解析PCAP文件，共 " << packets.size() << " 个数据包" << std::endl;
            
            // 将数据包导入到数据库
            if (sqliteUtil.insertPacket(packets)) {
                std::cout << "成功将数据包导入到数据库" << std::endl;
            } else {
                std::cerr << "导入数据包到数据库失败" << std::endl;
            }
        } else {
            std::cerr << "解析PCAP文件失败" << std::endl;
        }
    } else {
        std::cerr << "创建数据表失败" << std::endl;
    }

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

    return 0;
}
