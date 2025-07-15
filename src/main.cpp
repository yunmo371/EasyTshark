#include <array>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <thread>

#include "loguru.hpp"
#include "tsharkManager.hpp"
#include "utils.hpp"


int main(int argc, char* argv[])
{
    std::string ts               = CommonUtil::get_timestamp();
    std::string capture_log_name = "logs/capture_" + ts + ".log";
    loguru::init(argc, argv);
    loguru::add_file(capture_log_name.c_str(), loguru::Append, loguru::Verbosity_MAX);

    std::string dataDir  = "data";
    std::string mkdirCmd = "mkdir -p " + dataDir;
    std::system(mkdirCmd.c_str());

    TsharkManager tsharkManager("/home/dev/EasyTshark/output");

    int mode;
    std::cout << "请选择模式：\n1. 实时抓包\n2. 离线分析\n请输入选择 (1或2): ";
    std::cin >> mode;

    std::string dataPcapFile = dataDir + "/capture.pcap";

    if (mode == 1)
    {
        std::string rmCmd = "rm -rf " + dataDir + "/*";
        std::system(rmCmd.c_str());
        std::cout << "已清空data目录" << std::endl;
        std::vector<AdapterInfo> adapters = tsharkManager.getNetworkAdapterInfo();
        std::cout << "可用网卡列表：" << std::endl;
        for (const auto& adapter : adapters)
        {
            std::cout << adapter.id << ": " << adapter.name << " (" << adapter.remark << ")"
                      << std::endl;
        }

        std::string adapterName;
        std::cout << "请输入要监控的网卡名称: ";
        std::cin >> adapterName;

        int captureSeconds;
        std::cout << "请输入抓包时间(秒): ";
        std::cin >> captureSeconds;

        std::cout << "开始抓包，持续 " << captureSeconds << " 秒..." << std::endl;
        tsharkManager.startCapture(adapterName);

        std::this_thread::sleep_for(std::chrono::seconds(captureSeconds));

        tsharkManager.stopCapture();

        std::string pcapFile = "capture.pcap";
        std::string mvCmd    = "mv " + pcapFile + " " + dataPcapFile;
        std::system(mvCmd.c_str());
        std::cout << "抓包已完成，保存到 " << dataPcapFile << std::endl;
    }
    else if (mode == 2)
    {
        // 检查data目录是否已有capture.pcap文件
        std::ifstream existingFile(dataPcapFile);
        if (existingFile.good())
        {
            existingFile.close();
            char choice;
            std::cout << "发现已存在的抓包文件: " << dataPcapFile << std::endl;
            std::cout << "是否使用此文件？(y/n): ";
            std::cin >> choice;

            if (choice == 'y' || choice == 'Y')
            {
                std::cout << "使用现有文件: " << dataPcapFile << std::endl;
            }
            else
            {
                std::string pcapFilePath;
                std::cout << "请输入新的PCAP文件路径: ";
                std::cin >> pcapFilePath;

                // 复制文件到data目录
                std::string cpCmd = "cp " + pcapFilePath + " " + dataPcapFile;
                if (std::system(cpCmd.c_str()) != 0)
                {
                    std::cerr << "复制文件失败，请检查文件路径是否正确" << std::endl;
                    return 1;
                }
                std::cout << "文件已复制到 " << dataPcapFile << std::endl;
            }
        }
        else
        {
            std::string pcapFilePath;
            std::cout << "请输入PCAP文件路径: ";
            std::cin >> pcapFilePath;

            // 复制文件到data目录
            std::string cpCmd = "cp " + pcapFilePath + " " + dataPcapFile;
            if (std::system(cpCmd.c_str()) != 0)
            {
                std::cerr << "复制文件失败，请检查文件路径是否正确" << std::endl;
                return 1;
            }
            std::cout << "文件已复制到 " << dataPcapFile << std::endl;
        }
    }
    else
    {
        std::cerr << "无效的选择，程序退出" << std::endl;
        return 1;
    }

    std::string dbPath = dataDir + "/packets.db";
    SQLiteUtil  sqliteUtil(dbPath);

    if (sqliteUtil.createPacketTable())
    {
        std::cout << "成功创建数据表" << std::endl;

        // 解析PCAP文件到db
        std::vector<std::shared_ptr<Packet>> packets;
        if (tsharkManager.analysisFile(dataPcapFile, packets))
        {
            std::cout << "成功解析PCAP文件，共 " << packets.size() << " 个数据包" << std::endl;

            if (sqliteUtil.insertPacket(packets))
            {
                std::cout << "成功将数据包导入到数据库" << std::endl;
            }
            else
            {
                std::cerr << "导入数据包到数据库失败" << std::endl;
            }
        }
        else
        {
            std::cerr << "解析PCAP文件失败" << std::endl;
        }
    }
    else
    {
        std::cerr << "创建数据表失败" << std::endl;
    }

    // 将PCAP文件转换为XML
    std::string xmlFile = dataDir + "/packets.xml";
    if (tsharkManager.convertPcapToXml(dataPcapFile, xmlFile))
    {
        std::cout << "PCAP文件已成功转换为XML文件: " << xmlFile << std::endl;

        // 将XML文件转换为JSON
        std::string jsonFile = dataDir + "/packets.json";
        if (tsharkManager.convertXmlToJson(xmlFile, jsonFile))
        {
            std::cout << "处理完成！" << std::endl;

            char queryChoice;
            std::cout << "是否要查询数据包？(y/n): ";
            std::cin >> queryChoice;

            if (queryChoice == 'y' || queryChoice == 'Y')
            {
                while (true)
                {
                    std::string macAddr, ipAddr, port, location;
                    std::cout << "\n请输入查询条件（直接回车表示不使用该条件）：" << std::endl;

                    std::cout << "MAC地址（支持模糊匹配，如: 00:11:22:*）: ";
                    std::cin.ignore();
                    std::getline(std::cin, macAddr);

                    std::cout << "IP地址（支持模糊匹配，如: 192.168.*）: ";
                    std::getline(std::cin, ipAddr);

                    std::cout << "端口（支持模糊匹配，如: 80*）: ";
                    std::getline(std::cin, port);

                    std::cout << "归属地（支持模糊匹配，如: 深圳*）: ";
                    std::getline(std::cin, location);

                    // 构建查询条件
                    std::map<std::string, std::string> conditions;
                    if (!macAddr.empty())
                        conditions["mac_address"] = macAddr;
                    if (!ipAddr.empty())
                        conditions["ip_address"] = ipAddr;
                    if (!port.empty())
                        conditions["port"] = port;
                    if (!location.empty())
                        conditions["location"] = location;

                    if (conditions.empty())
                    {
                        std::cout << "未指定任何查询条件！" << std::endl;
                    }
                    else
                    {
                        // 执行查询并输出结果
                        std::string jsonResult;
                        if (sqliteUtil.queryPackets(conditions, jsonResult))
                        {
                            std::cout << "\n查询结果：" << std::endl;
                            std::cout << jsonResult << std::endl;

                            char saveChoice;
                            std::cout << "\n是否保存查询结果到文件？(y/n): ";
                            std::cin >> saveChoice;

                            if (saveChoice == 'y' || saveChoice == 'Y')
                            {
                                // 生成默认文件名（使用时间戳）
                                std::string timestamp       = CommonUtil::get_timestamp();
                                std::string defaultFileName = "data/query_" + timestamp + ".json";

                                std::cout << "默认保存到文件: " << defaultFileName << std::endl;
                                std::cout << "是否使用默认文件名？(y/n): ";
                                char useDefault;
                                std::cin >> useDefault;

                                std::string saveFilePath;
                                if (useDefault == 'y' || useDefault == 'Y')
                                {
                                    saveFilePath = defaultFileName;
                                }
                                else
                                {
                                    std::cout << "请输入保存文件路径: ";
                                    std::cin.ignore();
                                    std::getline(std::cin, saveFilePath);
                                }

                                if (sqliteUtil.saveQueryResultToFile(jsonResult, saveFilePath))
                                {
                                    std::cout << "查询结果已保存到: " << saveFilePath << std::endl;
                                }
                                else
                                {
                                    std::cerr << "保存查询结果失败！" << std::endl;
                                }
                            }
                        }
                        else
                        {
                            std::cerr << "查询失败！" << std::endl;
                        }
                    }

                    char continueQuery;
                    std::cout << "\n是否继续查询？(y/n): ";
                    std::cin >> continueQuery;
                    if (continueQuery != 'y' && continueQuery != 'Y')
                    {
                        break;
                    }
                }
            }
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
