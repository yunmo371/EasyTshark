#include<iomanip>
#include<array>

#include"loguru.hpp"
#include"utils.hpp"
#include"tsharkManager.hpp"


int main(int argc, char* argv[])
{   
    TsharkManager tsharkManager("/root/dev/learn_from_xuanyuan/output");
    std::string ts = get_timestamp();
    std::string log_name = "logs/log_" + ts + ".txt";
       
    loguru::init(argc, argv);
    loguru::add_file(log_name.c_str(), loguru::Append, loguru::Verbosity_MAX);

    tsharkManager.analysisFile("/home/capture.pcap");
    tsharkManager.printAllPackets();
    
    return 0;
}


