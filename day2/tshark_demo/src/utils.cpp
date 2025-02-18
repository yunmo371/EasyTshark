#include<ctime>
#include<chrono>
#include<iomanip>
#include<sstream>
#include"tsharkHead.hpp"

std::string get_timestamp()
{
    auto now = std::chrono::system_clock::now();
    std::time_t now_time_t = std::chrono::system_clock::to_time_t(now);
    std::tm* now_tm = std::localtime(&now_time_t);
    std::stringstream ss;
    ss << std::put_time(now_tm, "%Y%m%d%H%M%S");
    return ss.str();
}
