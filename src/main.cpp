#include <iomanip>
#include <array>

#include "loguru.hpp"
#include "utils.hpp"
#include "tsharkManager.hpp"

int main(int argc, char *argv[])
{
    TsharkManager tsharkManager("/root/dev/learn_from_xuanyuan/output");
    std::string ts = get_timestamp();
    std::string log_name = "logs/log_" + ts + ".txt";

    loguru::init(argc, argv);
    loguru::add_file(log_name.c_str(), loguru::Append, loguru::Verbosity_MAX);

    tsharkManager.analysisFile("/home/capture.pcap");
    tsharkManager.printAllPackets();
    std::vector<AdapterInfo> adaptors = tsharkManager.getNetworkAdapterInfo();
    for (auto item : adaptors)
    {
        LOG_F(INFO, "网卡[%d]: name[%s] remark[%s]", item.id, item.name.c_str(), item.remark.c_str());
    }
    return 0;
}
