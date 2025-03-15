#include <chrono>
#include <ctime>
#include <iconv.h>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "tsharkDataType.hpp"
#include "utils.hpp"

std::shared_ptr<xdb_search_t> IP2RegionUtil::xdbPtr;

std::string IP2RegionUtil::getIpLocation(const std::string& ip)
{

    // if is IPv6, return empty string
    if (ip.size() > 15)
    {
        return "";
    }

    std::string location = xdbPtr->search(ip);
    if (!location.empty() && location.find("invalid") == std::string::npos)
    {
        return parseLocation(location);
    }
    else
    {
        return "";
    }
}

std::string IP2RegionUtil::parseLocation(const std::string& input)
{
    std::vector<std::string> tokens;
    std::string              token;
    std::stringstream        ss(input);

    if (input.find("内网") != std::string::npos)
    {
        return "内网";
    }

    while (std::getline(ss, token, '|'))
    {
        tokens.push_back(token);
    }

    if (tokens.size() >= 4)
    {
        std::string result;
        if (tokens[0].compare("0") != 0)
        {
            result.append(tokens[0]);
        }
        if (tokens[2].compare("0") != 0)
        {
            result.append("-" + tokens[2]);
        }
        if (tokens[3].compare("0") != 0)
        {
            result.append("-" + tokens[3]);
        }

        return result;
    }
    else
    {
        return input;
    }
}

bool IP2RegionUtil::init(const std::string& xdbFilePath)
{

    xdbPtr = std::make_shared<xdb_search_t>(xdbFilePath);
    xdbPtr->init_content();
    return true;
}

std::string CommonUtil::UTF8ToANSIString(const std::string& utf8Str)
{
    if (utf8Str.empty())
        return "";

    iconv_t cd = iconv_open("ANSI", "UTF-8");
    if (cd == (iconv_t)-1)
        return "";

    size_t            inBytesLeft  = utf8Str.size();
    size_t            outBytesLeft = utf8Str.size() * 2;
    std::vector<char> outBuf(outBytesLeft);
    char*             inBuf     = const_cast<char*>(utf8Str.c_str());
    char*             outBufPtr = outBuf.data();

    if (iconv(cd, &inBuf, &inBytesLeft, &outBufPtr, &outBytesLeft) == (size_t)-1)
    {
        iconv_close(cd);
        return "";
    }

    iconv_close(cd);
    return std::string(outBuf.begin(), outBuf.begin() + (outBuf.size() - outBytesLeft));
}

std::string CommonUtil::get_timestamp()
{
    auto              now        = std::chrono::system_clock::now();
    std::time_t       now_time_t = std::chrono::system_clock::to_time_t(now);
    std::tm*          now_tm     = std::localtime(&now_time_t);
    std::stringstream ss;
    // 获取自纪元以来的总时间（纳秒级）
    auto duration_since_epoch = now.time_since_epoch();
    // 转换为秒
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration_since_epoch);
    // 剩余的纳秒部分
    auto nanoseconds =
        std::chrono::duration_cast<std::chrono::nanoseconds>(duration_since_epoch - seconds);
    // 转换为微秒
    long long microseconds = nanoseconds.count() / 1000;

    // 格式化时间字符串
    ss << std::put_time(now_tm, "%Y-%m-%d %H:%M:%S") << "." << std::setw(6) << std::setfill('0')
       << microseconds;

    return ss.str();
}
