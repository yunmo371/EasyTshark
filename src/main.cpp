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

    // 抓包
    tsharkManager.startCapture("eth0");
    std::string input;
    while (true)
    {
        std::cout << "请输入q退出抓包: ";
        std::cin >> input;
        if (input == "q")
        {
            tsharkManager.stopCapture();
            break;
        }
    }
    // 解包
    std::string analysis_log_name = "logs/analysis_log_" + ts + ".txt";
    loguru::add_file(analysis_log_name.c_str(), loguru::Append, loguru::Verbosity_MAX);
    tsharkManager.analysisFile("capture.pcap");
    tsharkManager.printAllPackets();
    // std::vector<AdapterInfo> adaptors = tsharkManager.getNetworkAdapterInfo();
    // for (auto item : adaptors)
    // {
    //     LOG_F(INFO, "网卡[%d]: name[%s] remark[%s]", item.id, item.name.c_str(), item.remark.c_str());
    // }
    return 0;
}
