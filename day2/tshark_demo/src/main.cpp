#include<iostream>
#include<memory>
#include<array>
#include<vector>
#include<sstream>

#include"loguru.hpp"
#include"utils.hpp"
#include"tsharkHead.hpp"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"


void parseLine(std::string line, Packet& packet)
{
    if (line.back() == '\n') {
        line.pop_back();
    }
    std::stringstream ss(line);
    std::string field;
    std::vector<std::string> fields;

    while (std::getline(ss, field, '\t')) {  // 假设字段用 tab 分隔
        fields.push_back(field);
    }

    if (fields.size() >= 6) {
        packet.frame_number = std::stoi(fields[0]);
        packet.time = fields[1];
        packet.src_ip = fields[2];
        packet.dst_ip = fields[3];
        packet.protocol = fields[4];
        packet.info = fields[5];
    }
}

void printPacket(const Packet &packet) {

    // 构建JSON对象
    rapidjson::Document pktObj;
    rapidjson::Document::AllocatorType& allocator = pktObj.GetAllocator();

    // 设置JSON为Object对象类型
    pktObj.SetObject();

    // 添加JSON字段
    pktObj.AddMember("frame_number", packet.frame_number, allocator);
    pktObj.AddMember("timestamp", rapidjson::Value(packet.time.empty() ? "(unkonw)" : packet.time.c_str(), allocator), allocator);
    pktObj.AddMember("src_ip", rapidjson::Value(packet.src_ip.empty() ? "(unkonw)" : packet.src_ip.c_str(), allocator), allocator);
    pktObj.AddMember("dst_ip", rapidjson::Value(packet.dst_ip.empty() ? "(unkonw)" : packet.dst_ip.c_str(), allocator), allocator);
    pktObj.AddMember("protocol", rapidjson::Value(packet.protocol.empty() ? "(443)" : packet.protocol.c_str(), allocator), allocator);
    pktObj.AddMember("info", rapidjson::Value(packet.info.empty() ? "(unkonw)" : packet.info.c_str(), allocator), allocator);

    // 序列化为 JSON 字符串
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    pktObj.Accept(writer);

    // 打印JSON输出
    // std::cout << buffer.GetString() << std::endl;
    LOG_F(INFO, buffer.GetString());
}

std::string exec_1(const char* cmd)
{
    std::array<char, 128> buffer;
    std::string res;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);

    if(!pipe)
    {
        LOG_F(ERROR,"Failed to run tshark command : %s", cmd);
        return "";
    }
    while(fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
    {
        res += buffer.data();
    }
    return res;
}

std::string exec_2(const char* cmd)
{
    std::array<char, 128> buffer;
    // std::string output;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    std::vector<Packet> packets;

    if(!pipe)
    {
        LOG_F(ERROR,"Failed to run tshark command : %s", cmd);
        return "";
    }
    while(fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
    {
        Packet packet;
        parseLine(buffer.data(), packet);
        packets.push_back(packet);
    }
    // for (auto &p : packets) {
    //     output = "frame_number: %d  time: %s  src_ip: %s  dst_ip: %s  protocol: %s  info: %s\n",
    //     p.frame_number,
    //     p.time.empty() ? "(unkonw)" : p.time.c_str(),
    //     p.src_ip.empty() ? "(unkonw)" : p.src_ip.c_str(),
    //     p.dst_ip.empty() ? "(unkonw)" : p.dst_ip.c_str(),
    //     p.protocol.empty() ? "(unkonw)" : p.protocol.c_str(),
    //     p.info.empty() ? "(unkonw)" : p.info.c_str();
    //     LOG_F(INFO, output.c_str());
    // }
    for(auto&p : packets)
    {
        printPacket(p);
        break;
    }
    
    return "";
}


int main(int argc, char* argv[])
{   
    std::string ts = get_timestamp();
    std::string log_name = "logs/log_" + ts + ".txt";

    loguru::init(argc, argv);
    loguru::add_file(log_name.c_str(), loguru::Truncate, loguru::Verbosity_MAX);

    // const char* cmd = "/usr/bin/tshark -r /home/capture.pcap";
    // std::string output = exec_1(cmd);
    // LOG_F(INFO, output.c_str());

    const char* cmd = "/usr/bin/tshark -r /home/capture.pcap -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info";
    exec_2(cmd);
    
    return 0;
}