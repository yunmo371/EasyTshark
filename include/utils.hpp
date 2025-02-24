#ifndef utils_hpp
#define utils_hpp

#include<string>
#include<memory>
#include "ip2region/xdb_search.h"

std::string get_timestamp();

std::string UTF8ToANSIString(const std::string& utf8Str);

class IP2RegionUtil {
public:
    static bool init(const std::string& xdbFilePath);
    static std::string getIpLocation(const std::string& ip);

private:
    static std::string parseLocation(const std::string& input);
    static std::shared_ptr<xdb_search_t> xdbPtr;
};
#endif