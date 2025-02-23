#include<iconv.h>
#include<string>
#include<vector>
#include<stdexcept>
#include<ctime>
#include<chrono>
#include<iomanip>
#include<sstream>
#include"tsharkHead.hpp"


std::string UTF8ToANSIString(const std::string& utf8Str)
{
    const char* toEncoding = "GBK";
    const char* fromEncoding = "UTF-8";
    iconv_t cd = iconv_open("GBK", "UTF-8");
    if(cd == (iconv_t)-1)
    {
        throw std::runtime_error("iconv_open failed");
    }
    const char* inBuf = utf8Str.c_str();
    size_t inBytesLeft = utf8Str.size();

    std::vector<char> outBuf(inBytesLeft * 2);
    char* outBufPtr = outBuf.data();
    size_t outBytesLeft = outBuf.size();

    iconv_close(cd);
    size_t resultSize = outBuf.size() - outBytesLeft;
    outBuf.resize(resultSize);

    return std::string(outBuf.begin(), outBuf.end());
}

std::string get_timestamp()
{
    auto now = std::chrono::system_clock::now();
    std::time_t now_time_t = std::chrono::system_clock::to_time_t(now);
    std::tm* now_tm = std::localtime(&now_time_t);
    std::stringstream ss;
    ss << std::put_time(now_tm, "%Y%m%d%H%M%S");
    return ss.str();
}
