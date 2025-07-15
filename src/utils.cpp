#include <algorithm>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iconv.h>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "loguru.hpp"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include "ip2region/xdb_search.h"
#include "tsharkDataType.hpp"
#include "utils.hpp"
#include <sqlite3.h>


std::unordered_map<std::string, std::string> translationMap = {
    {"General information", "常规信息"},
    {"Frame Number", "帧编号"},
    {"Captured Length", "捕获长度"},
    {"Captured Time", "捕获时间"},
    {"Section number", "节号"},
    {"Interface id", "接口 id"},
    {"Interface name", "接口名称"},
    {"Encapsulation type", "封装类型"},
    {"Arrival Time", "到达时间"},
    {"UTC Arrival Time", "UTC到达时间"},
    {"Epoch Arrival Time", "纪元到达时间"},
    {"Time shift for this packet", "该数据包的时间偏移"},
    {"Time delta from previous captured frame", "与上一个捕获帧的时间差"},
    {"Time delta from previous displayed frame", "与上一个显示帧的时间差"},
    {"Time since reference or first frame", "自参考帧或第一帧以来的时间"},
    {"Frame Number", "帧编号"},
    {"Frame Length", "帧长度"},
    {"Capture Length", "捕获长度"},
    {"Frame is marked", "帧标记"},
    {"Frame is ignored", "帧忽略"},
    {"Frame", "帧"},
    {"Protocols in frame", "帧中的协议"},
    {"Ethernet II", "以太网 II"},
    {"Destination", "目的地址"},
    {"Address Resolution Protocol", "ARP地址解析地址"},
    {"Address (resolved)", "地址（解析后）"},
    {"Type", "类型"},
    {"Stream index", "流索引"},
    {"Internet Protocol Version 4", "互联网协议版本 4"},
    {"Internet Protocol Version 6", "互联网协议版本 6"},
    {"Internet Control Message Protocol", "互联网控制消息协议ICMP"},
    {"Version", "版本"},
    {"Header Length", "头部长度"},
    {"Differentiated Services Field", "差分服务字段"},
    {"Total Length", "总长度"},
    {"Identification", "标识符"},
    {"Flags", "标志"},
    {"Time to Live", "生存时间"},
    {"Transmission Control Protocol", "TCP传输控制协议"},
    {"User Datagram Protocol", "UDP用户数据包协议"},
    {"Domain Name System", "DNS域名解析系统"},
    {"Header Checksum", "头部校验和"},
    {"Header checksum status", "校验和状态"},
    {"Source Address", "源地址"},
    {"Destination Address", "目的地址"},
    {"Source Port", "源端口"},
    {"Destination Port", "目的端口"},
    {"Next Sequence Number", "下一个序列号"},
    {"Sequence Number", "序列号"},
    {"Acknowledgment Number", "确认号"},
    {"Acknowledgment number", "确认号"},
    {"TCP Segment Len", "TCP段长度"},
    {"Conversation completeness", "会话完整性"},
    {"Window size scaling factor", "窗口缩放因子"},
    {"Calculated window size", "计算窗口大小"},
    {"Window", "窗口"},
    {"Urgent Pointer", "紧急指针"},
    {"Checksum:", "校验和:"},
    {"TCP Option - Maximum segment size", "TCP选项 - 最大段大小"},
    {"Kind", "种类"},
    {"MSS Value", "MSS值"},
    {"TCP Option - Window scale", "TCP选项 - 窗口缩放"},
    {"Shift count", "移位计数"},
    {"Multiplier", "倍数"},
    {"TCP Option - Timestamps", "TCP选项 - 时间戳"},
    {"TCP Option - SACK permitted", "TCP选项 - SACK 允许"},
    {"TCP Option - End of Option List", "TCP选项 - 选项列表结束"},
    {"Options", "选项"},
    {"TCP Option - No-Operation", "TCP选项 - 无操作"},
    {"Timestamps", "时间戳"},
    {"Time since first frame in this TCP stream", "自第一帧以来的时间"},
    {"Time since previous frame in this TCP stream", "与上一个帧的时间差"},
    {"Protocol:", "协议:"},
    {"Source:", "源地址:"},
    {"Length:", "长度:"},
    {"Checksum status", "校验和状态"},
    {"Checksum Status", "校验和状态"},
    {"TCP payload", "TCP载荷"},
    {"UDP payload", "UDP载荷"},
    {"Hypertext Transfer Protocol", "超文本传输协议HTTP"},
    {"Transport Layer Security", "传输层安全协议TLS"}};

// 创建map版本的translationMap2，内容与translationMap相同
std::map<std::string, std::string> translationMap2 = {
    {"General information", "常规信息"},
    {"Frame Number", "帧编号"},
    {"Captured Length", "捕获长度"},
    {"Captured Time", "捕获时间"},
    {"Section number", "节号"},
    {"Interface id", "接口 id"},
    {"Interface name", "接口名称"},
    {"Encapsulation type", "封装类型"},
    {"Arrival Time", "到达时间"},
    {"UTC Arrival Time", "UTC到达时间"},
    {"Epoch Arrival Time", "纪元到达时间"},
    {"Time shift for this packet", "该数据包的时间偏移"},
    {"Time delta from previous captured frame", "与上一个捕获帧的时间差"},
    {"Time delta from previous displayed frame", "与上一个显示帧的时间差"},
    {"Time since reference or first frame", "自参考帧或第一帧以来的时间"},
    {"Frame Number", "帧编号"},
    {"Frame Length", "帧长度"},
    {"Capture Length", "捕获长度"},
    {"Frame is marked", "帧标记"},
    {"Frame is ignored", "帧忽略"},
    {"Frame", "帧"},
    {"Protocols in frame", "帧中的协议"},
    {"Ethernet II", "以太网 II"},
    {"Destination", "目的地址"},
    {"Address Resolution Protocol", "ARP地址解析地址"},
    {"Address (resolved)", "地址（解析后）"},
    {"Type", "类型"},
    {"Stream index", "流索引"},
    {"Internet Protocol Version 4", "互联网协议版本 4"},
    {"Internet Protocol Version 6", "互联网协议版本 6"},
    {"Internet Control Message Protocol", "互联网控制消息协议ICMP"},
    {"Version", "版本"},
    {"Header Length", "头部长度"},
    {"Differentiated Services Field", "差分服务字段"},
    {"Total Length", "总长度"},
    {"Identification", "标识符"},
    {"Flags", "标志"},
    {"Time to Live", "生存时间"},
    {"Transmission Control Protocol", "TCP传输控制协议"},
    {"User Datagram Protocol", "UDP用户数据包协议"},
    {"Domain Name System", "DNS域名解析系统"},
    {"Header Checksum", "头部校验和"},
    {"Header checksum status", "校验和状态"},
    {"Source Address", "源地址"},
    {"Destination Address", "目的地址"},
    {"Source Port", "源端口"},
    {"Destination Port", "目的端口"},
    {"Next Sequence Number", "下一个序列号"},
    {"Sequence Number", "序列号"},
    {"Acknowledgment Number", "确认号"},
    {"Acknowledgment number", "确认号"},
    {"TCP Segment Len", "TCP段长度"},
    {"Conversation completeness", "会话完整性"},
    {"Window size scaling factor", "窗口缩放因子"},
    {"Calculated window size", "计算窗口大小"},
    {"Window", "窗口"},
    {"Urgent Pointer", "紧急指针"},
    {"Checksum:", "校验和:"},
    {"TCP Option - Maximum segment size", "TCP选项 - 最大段大小"},
    {"Kind", "种类"},
    {"MSS Value", "MSS值"},
    {"TCP Option - Window scale", "TCP选项 - 窗口缩放"},
    {"Shift count", "移位计数"},
    {"Multiplier", "倍数"},
    {"TCP Option - Timestamps", "TCP选项 - 时间戳"},
    {"TCP Option - SACK permitted", "TCP选项 - SACK 允许"},
    {"TCP Option - End of Option List", "TCP选项 - 选项列表结束"},
    {"Options", "选项"},
    {"TCP Option - No-Operation", "TCP选项 - 无操作"},
    {"Timestamps", "时间戳"},
    {"Time since first frame in this TCP stream", "自第一帧以来的时间"},
    {"Time since previous frame in this TCP stream", "与上一个帧的时间差"},
    {"Protocol:", "协议:"},
    {"Source:", "源地址:"},
    {"Length:", "长度:"},
    {"Checksum status", "校验和状态"},
    {"Checksum Status", "校验和状态"},
    {"TCP payload", "TCP载荷"},
    {"UDP payload", "UDP载荷"},
    {"Hypertext Transfer Protocol", "超文本传输协议HTTP"},
    {"Transport Layer Security", "传输层安全协议TLS"}};

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
    auto now      = std::chrono::system_clock::now();
    auto now_time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_time), "%Y%m%d%H%M%S");
    ss << std::setfill('0') << std::setw(3) << ms.count();

    return ss.str();
}


void CommonUtil::translateShowNameFields(rapidjson::Value&                   value,
                                         rapidjson::Document::AllocatorType& allocator)
{
    if (value.IsObject())
    {
        if (value.HasMember("showname") && value["showname"].IsString())
        {
            std::string showname = value["showname"].GetString();

            for (const auto& pair : translationMap)
            {
                const std::string& key         = pair.first;
                const std::string& translation = pair.second;

                if (showname.find(key) == 0)
                {
                    showname.replace(0, key.length(), translation);
                    value["showname"].SetString(showname.c_str(), allocator);
                    break;
                }
            }
        }
        else if (value.HasMember("show") && value["show"].IsString())
        {
            std::string showname = value["show"].GetString();

            for (const auto& pair : translationMap)
            {
                const std::string& key         = pair.first;
                const std::string& translation = pair.second;

                if (showname.find(key) == 0)
                {
                    showname.replace(0, key.length(), translation);
                    value["show"].SetString(showname.c_str(), allocator);
                    break;
                }
            }
        }

        // 有 "field" 字段，递归处理
        if (value.HasMember("field") && value["field"].IsArray())
        {
            rapidjson::Value& fieldArray = value["field"];
            for (auto& field : fieldArray.GetArray())
            {
                translateShowNameFields(field, allocator);
            }
        }
    }
    else if (value.IsArray())
    {
        for (auto& item : value.GetArray())
        {
            translateShowNameFields(item, allocator);
        }
    }
}

// 性能对比函数实现
void CommonUtil::compareMapPerformance(int iterations)
{
    try
    {
        std::string key = "Interface id";

        // unordered_map
        std::string result;
        auto        start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i)
        {
            auto it = translationMap.find(key);
            if (it != translationMap.end())
            {
                result = it->second;
            }
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto unordered_duration =
            std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

        // map
        start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i)
        {
            auto it = translationMap2.find(key);
            if (it != translationMap2.end())
            {
                result = it->second;
            }
        }
        end = std::chrono::high_resolution_clock::now();
        auto map_duration =
            std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

        std::cout << "unordered_map 查询" << iterations << "次耗时: " << unordered_duration << " us"
                  << std::endl;
        std::cout << "map 查询" << iterations << "次耗时: " << map_duration << " us" << std::endl;

        if (unordered_duration > 0)
        {
            std::cout << "对比结果: unordered_map是map的"
                      << static_cast<double>(map_duration) / unordered_duration << "倍速度"
                      << std::endl;
        }
        else
        {
            std::cout << "无法计算性能比较，unordered_map耗时为0" << std::endl;
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "性能比较过程中发生异常: " << e.what() << std::endl;
    }
    catch (...)
    {
        std::cerr << "性能比较过程中发生未知异常" << std::endl;
    }
}

SQLiteUtil::SQLiteUtil(const std::string& dbname)
{
    // 打开数据库连接
    int rc = sqlite3_open(dbname.c_str(), &db);
    if (rc != SQLITE_OK)
    {
        LOG_F(ERROR, "Failed to open database: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        throw std::runtime_error("Failed to open database");
    }
}

SQLiteUtil::~SQLiteUtil()
{
    if (db)
    {
        sqlite3_close(db);
        db = nullptr;
    }
}

bool SQLiteUtil::createPacketTable()
{
    // 检查表是否存在，若不存在则创建
    std::string createTableSQL = R"(
        CREATE TABLE IF NOT EXISTS t_packets (
            frame_number INTEGER PRIMARY KEY,
            time REAL,
            cap_len INTEGER,
            len INTEGER,
            src_mac TEXT,
            dst_mac TEXT,
            src_ip TEXT,
            src_location TEXT,
            src_port INTEGER,
            dst_ip TEXT,
            dst_location TEXT,
            dst_port INTEGER,
            protocol TEXT,
            info TEXT,
            file_offset INTEGER
        );
    )";

    if (db == nullptr)
    {
        LOG_F(ERROR, "Database connection is not initialized");
        return false;
    }

    if (sqlite3_exec(db, createTableSQL.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK)
    {
        LOG_F(ERROR, "Failed to create table t_packets: %s", sqlite3_errmsg(db));
        return false;
    }

    return true;
}

bool SQLiteUtil::insertPacket(std::vector<std::shared_ptr<Packet>>& packets)
{
    // 实现插入数据的逻辑
    // 开启事务
    sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

    // SQL 插入语句
    std::string insertSQL = R"(
        INSERT INTO t_packets (
            frame_number, time, cap_len, len, src_mac, dst_mac, src_ip, src_location, src_port,
            dst_ip, dst_location, dst_port, protocol, info, file_offset
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, insertSQL.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
    {
        LOG_F(ERROR, "Failed to prepare insert statement: %s", sqlite3_errmsg(db));
        return false;
    }

    // 遍历列表并插入数据
    bool hasError = false;
    for (const auto& packet : packets)
    {
        sqlite3_bind_int(stmt, 1, packet->frame_number);
        sqlite3_bind_double(stmt, 2, packet->time);
        sqlite3_bind_int(stmt, 3, packet->cap_len);
        sqlite3_bind_int(stmt, 4, packet->len);
        sqlite3_bind_text(stmt, 5, packet->src_mac.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, packet->dst_mac.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 7, packet->src_ip.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 8, packet->src_location.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 9, packet->src_port);
        sqlite3_bind_text(stmt, 10, packet->dst_ip.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 11, packet->dst_location.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 12, packet->dst_port);
        sqlite3_bind_text(stmt, 13, packet->protocol.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 14, packet->info.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 15, packet->file_offset);

        if (sqlite3_step(stmt) != SQLITE_DONE)
        {
            LOG_F(ERROR, "Failed to execute insert statement: %s", sqlite3_errmsg(db));
            hasError = true;
            break;
        }

        sqlite3_reset(stmt); // 重置语句以便下一次绑定
    }

    // 释放语句
    sqlite3_finalize(stmt);

    if (!hasError)
    {
        // 结束事务
        if (sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr) != SQLITE_OK)
        {
            LOG_F(ERROR, "Failed to commit transaction: %s", sqlite3_errmsg(db));
            hasError = true;
        }
    }
    else
    {
        // 如果有错误，回滚事务
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
    }

    return !hasError;
}

bool SQLiteUtil::queryPacket(std::vector<std::shared_ptr<Packet>>& packetList)
{
    sqlite3_stmt *stmt = nullptr, *countStmt = nullptr;
    std::string   sql = "select * from t_packets";
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
    {
        LOG_F(ERROR, "Failed to prepare statement: ");
        return false;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        packet->frame_number           = sqlite3_column_int(stmt, 0);
        packet->time                   = sqlite3_column_double(stmt, 1);
        packet->cap_len                = sqlite3_column_int(stmt, 2);
        packet->len                    = sqlite3_column_int(stmt, 3);
        packet->src_mac      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        packet->dst_mac      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        packet->src_ip       = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        packet->src_location = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        packet->src_port     = sqlite3_column_int(stmt, 8);
        packet->dst_ip       = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
        packet->dst_location = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        packet->dst_port     = sqlite3_column_int(stmt, 11);
        packet->protocol     = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
        packet->info         = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 13));
        packet->file_offset  = sqlite3_column_int(stmt, 14);
        packetList.push_back(packet);
    }

    sqlite3_finalize(stmt);

    return true;
}

std::string SQLiteUtil::buildFuzzyQuery(const std::map<std::string, std::string>& conditions)
{
    std::string sql = "SELECT * FROM t_packets WHERE 1=1";

    for (const auto& condition : conditions)
    {
        if (condition.first == "mac_address")
        {
            std::string pattern = condition.second;
            std::replace(pattern.begin(), pattern.end(), '*', '%');
            sql += " AND (src_mac LIKE '" + pattern + "' OR dst_mac LIKE '" + pattern + "')";
        }
        else if (condition.first == "ip_address")
        {
            std::string pattern = condition.second;
            std::replace(pattern.begin(), pattern.end(), '*', '%');
            sql += " AND (src_ip LIKE '" + pattern + "' OR dst_ip LIKE '" + pattern + "')";
        }
        else if (condition.first == "port")
        {
            std::string pattern = condition.second;
            std::replace(pattern.begin(), pattern.end(), '*', '%');
            // 将字符串转换为数字进行比较
            if (pattern.find('%') == std::string::npos)
            {
                sql += " AND (src_port = " + pattern + " OR dst_port = " + pattern + ")";
            }
            else
            {
                sql += " AND (CAST(src_port AS TEXT) LIKE '" + pattern +
                       "' OR CAST(dst_port AS TEXT) LIKE '" + pattern + "')";
            }
        }
        else if (condition.first == "location")
        {
            std::string pattern = condition.second;
            std::replace(pattern.begin(), pattern.end(), '*', '%');
            // pattern前后都添加%，实现任意位置匹配
            if (pattern.find('%') == std::string::npos)
            {
                pattern = "%" + pattern + "%";
            }
            sql +=
                " AND (src_location LIKE '" + pattern + "' OR dst_location LIKE '" + pattern + "')";
        }
    }

    // sql += " ORDER BY frame_number ASC LIMIT 1000"; // 限制返回结果数量
    return sql;
}

std::string SQLiteUtil::packetsToJson(std::vector<std::shared_ptr<Packet>>& packets)
{
    rapidjson::Document document;
    document.SetObject();
    rapidjson::Document::AllocatorType& allocator = document.GetAllocator();

    document.AddMember("total", rapidjson::Value((int)packets.size()), allocator);

    rapidjson::Value packetsArray(rapidjson::kArrayType);

    for (const auto& packet : packets)
    {
        rapidjson::Value packetObj(rapidjson::kObjectType);

        packetObj.AddMember("frame_number", rapidjson::Value(packet->frame_number), allocator);
        packetObj.AddMember("time", rapidjson::Value(packet->time), allocator);
        packetObj.AddMember("cap_len", rapidjson::Value(packet->cap_len), allocator);
        packetObj.AddMember("len", rapidjson::Value(packet->len), allocator);
        packetObj.AddMember("src_mac", rapidjson::Value(packet->src_mac.c_str(), allocator),
                            allocator);
        packetObj.AddMember("dst_mac", rapidjson::Value(packet->dst_mac.c_str(), allocator),
                            allocator);
        packetObj.AddMember("src_ip", rapidjson::Value(packet->src_ip.c_str(), allocator),
                            allocator);
        packetObj.AddMember("src_location",
                            rapidjson::Value(packet->src_location.c_str(), allocator), allocator);
        packetObj.AddMember("src_port", rapidjson::Value(packet->src_port), allocator);
        packetObj.AddMember("dst_ip", rapidjson::Value(packet->dst_ip.c_str(), allocator),
                            allocator);
        packetObj.AddMember("dst_location",
                            rapidjson::Value(packet->dst_location.c_str(), allocator), allocator);
        packetObj.AddMember("dst_port", rapidjson::Value(packet->dst_port), allocator);
        packetObj.AddMember("protocol", rapidjson::Value(packet->protocol.c_str(), allocator),
                            allocator);
        packetObj.AddMember("info", rapidjson::Value(packet->info.c_str(), allocator), allocator);
        packetObj.AddMember("file_offset", rapidjson::Value(packet->file_offset), allocator);

        packetsArray.PushBack(packetObj, allocator);
    }

    document.AddMember("packets", packetsArray, allocator);

    rapidjson::StringBuffer                    buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    document.Accept(writer);

    return buffer.GetString();
}

bool SQLiteUtil::queryPackets(const std::map<std::string, std::string>& conditions,
                              std::string&                              jsonResult)
{
    std::string sql = buildFuzzyQuery(conditions);

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
    {
        LOG_F(ERROR, "Failed to prepare query statement: %s", sqlite3_errmsg(db));
        return false;
    }

    std::vector<std::shared_ptr<Packet>> packets;
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        packet->frame_number           = sqlite3_column_int(stmt, 0);
        packet->time                   = sqlite3_column_double(stmt, 1);
        packet->cap_len                = sqlite3_column_int(stmt, 2);
        packet->len                    = sqlite3_column_int(stmt, 3);
        packet->src_mac      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        packet->dst_mac      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        packet->src_ip       = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        packet->src_location = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        packet->src_port     = sqlite3_column_int(stmt, 8);
        packet->dst_ip       = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
        packet->dst_location = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        packet->dst_port     = sqlite3_column_int(stmt, 11);
        packet->protocol     = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
        packet->info         = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 13));
        packet->file_offset  = sqlite3_column_int(stmt, 14);
        packets.push_back(packet);
    }

    sqlite3_finalize(stmt);

    jsonResult = packetsToJson(packets);

    return true;
}

/**
 * @brief 将查询结果保存到JSON文件
 *
 * @param jsonResult JSON格式的查询结果字符串
 * @param filePath 保存文件的路径
 * @return true 保存成功
 * @return false 保存失败
 *
 * @note 如果目标文件已存在，将会被覆盖
 */
bool SQLiteUtil::saveQueryResultToFile(const std::string& jsonResult, const std::string& filePath)
{
    try
    {
        std::ofstream jsonFileStream(filePath);
        if (!jsonFileStream.is_open())
        {
            LOG_F(ERROR, "无法打开文件进行写入: %s", filePath.c_str());
            return false;
        }

        jsonFileStream << jsonResult;
        jsonFileStream.flush();
        if (jsonFileStream.fail())
        {
            LOG_F(ERROR, "写入文件时发生错误: %s", filePath.c_str());
            jsonFileStream.close();
            return false;
        }

        jsonFileStream.close();

        LOG_F(INFO, "查询结果已成功保存到文件: %s", filePath.c_str());
        return true;
    }
    catch (const std::exception& e)
    {
        LOG_F(ERROR, "保存查询结果时发生错误: %s", e.what());
        return false;
    }
}