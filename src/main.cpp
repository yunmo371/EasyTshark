#include <iomanip>
#include <array>

#include "loguru.hpp"
#include "utils.hpp"
#include "tsharkManager.hpp"

int main(int argc, char *argv[])
{
    TsharkManager tsharkManager("/root/dev/learn_from_xuanyuan/output");
    std::string ts = get_timestamp();
    std::string capture_log_name = "logs/catch_log_" + ts + ".txt";
    // std::string capture_log_name  = "logs/log_" + ts + ".txt";
    loguru::init(argc, argv);
    loguru::add_file(capture_log_name.c_str(), loguru::Append, loguru::Verbosity_MAX);

    // 启动监控
    tsharkManager.startMonitorAdaptersFlowTrend();

    // 睡眠10秒，等待监控网卡数据
    std::this_thread::sleep_for(std::chrono::seconds(10));

    // 读取监控到的数据
    std::map<std::string, std::map<long, long>> trendData;
    tsharkManager.getAdaptersFlowTrendData(trendData);

    // 停止监控
    tsharkManager.stopMonitorAdaptersFlowTrend();

    // 把获取到的数据打印输出
    rapidjson::Document resDoc;
    rapidjson::Document::AllocatorType &allocator = resDoc.GetAllocator();
    resDoc.SetObject();
    rapidjson::Value dataObject(rapidjson::kObjectType);
    for (const auto &adaptorItem : trendData)
    {
        rapidjson::Value adaptorDataList(rapidjson::kArrayType);
        for (const auto &timeItem : adaptorItem.second)
        {
            rapidjson::Value timeObj(rapidjson::kObjectType);
            timeObj.AddMember("time", (unsigned int)timeItem.first, allocator);
            timeObj.AddMember("bytes", (unsigned int)timeItem.second, allocator);
            adaptorDataList.PushBack(timeObj, allocator);
        }

        dataObject.AddMember(rapidjson::StringRef(adaptorItem.first.c_str()), adaptorDataList, allocator);
    }

    resDoc.AddMember("data", dataObject, allocator);

    // 序列化为 JSON 字符串
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    resDoc.Accept(writer);

    LOG_F(INFO, "网卡流量监控数据: %s", buffer.GetString());

    // // 抓包
    // tsharkManager.startCapture("eth0");
    // std::string input;
    // while (true)
    // {
    //     std::cout << "请输入q退出抓包: ";
    //     std::cin >> input;
    //     if (input == "q")
    //     {
    //         tsharkManager.stopCapture();
    //         break;
    //     }
    // }
    // // 解包
    // std::string analysis_log_name = "logs/analysis_log_" + ts + ".txt";
    // loguru::add_file(analysis_log_name.c_str(), loguru::Append, loguru::Verbosity_MAX);
    // tsharkManager.analysisFile("capture.pcap");
    // tsharkManager.printAllPackets();

    // std::vector<AdapterInfo> adaptors = tsharkManager.getNetworkAdapterInfo();
    // for (auto item : adaptors)
    // {
    //     LOG_F(INFO, "网卡[%d]: name[%s] remark[%s]", item.id, item.name.c_str(), item.remark.c_str());
    // }
    return 0;
}
