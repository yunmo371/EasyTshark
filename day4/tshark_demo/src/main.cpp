#include<iostream>
#include<fstream>
#include<iomanip>
#include<memory>
#include<array>
#include<vector>
#include<sstream>

#include"loguru.hpp"
#include"utils.hpp"
#include"tsharkHead.hpp"
#include"rapidjson/document.h"
#include"rapidjson/writer.h"
#include"rapidjson/prettywriter.h"
#include"rapidjson/stringbuffer.h"


bool parseLine(std::string line, Packet& packet) 
{
    // line = UTF8ToANSIString(line);

    if (line.back() == '\n') {
        line.pop_back();
    }
    std::stringstream ss(line);
    std::string field;
    std::vector<std::string> fields;

    size_t start = 0, end;
    while((end = line.find('\t', start)) != std::string::npos){
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(line.substr(start)); 
    // while (std::getline(ss, field, '\t')) {  // 假设字段用 tab 分隔
    //     fields.push_back(field);
    // }
    
    // 字段顺序：-e frame.number -e frame.time -e frame.cap_len -e ip.src -e ipv6.src -e ip.dst -e ipv6.dst
    // -e tcp.srcport -e udp.srcport -e tcp.dstport -e udp.dstport -e _ws.col.Protocol -e _ws.col.Info
    // 0: frame.number
    // 1: frame.time
    // 2: frame.cap_len
    // 3: ip.src
    // 4: ipv6.src
    // 5: ip.dst
    // 6: ipv6.dst
    // 7: tcp.srcport
    // 8: udp.srcport
    // 9: tcp.dstport
    // 10: udp.dstport
    // 11: _ws.col.Protocol
    // 12: _ws.col.Info

    // test ip
    IP2RegionUtil ip2RegionUtil;
    ip2RegionUtil.init("/home/ip2region.xdb");

    if (fields.size() >= 13) {
        packet.frame_number = std::stoi(fields[0]);
        packet.time = fields[1];
        packet.cap_len = std::stoi(fields[2]);
        packet.src_ip = fields[3].empty() ? fields[4] : fields[3];
        packet.src_addr = ip2RegionUtil.getIpLocation(packet.src_ip);
        packet.dst_ip = fields[5].empty() ? fields[6] : fields[5];
        packet.dst_addr = ip2RegionUtil.getIpLocation(packet.dst_ip);
        if (!fields[7].empty() || !fields[8].empty()) {
            packet.src_port = std::stoi(fields[7].empty() ? fields[8] : fields[7]);
        }

        if (!fields[9].empty() || !fields[10].empty()) {
            packet.dst_port = std::stoi(fields[9].empty() ? fields[10] : fields[9]);
        }
        packet.protocol = fields[11];
        packet.info = fields[12];
        return true;
    }else{
        printf("error!\n");
        return false;
    }
}

bool readPacketHex(const std::string& filePath, uint32_t offset, uint32_t cap_len, std::vector<unsigned char> &buffer)
{
    std::ifstream file(filePath, std::ios::binary);
    if(!file)
    {
        LOG_F(ERROR, "packet_file open failed");
    }
    file.seekg(offset);
    if(file.fail())
    {
        LOG_F(ERROR, "not found location");
    }
    buffer.resize(cap_len);
    file.read(reinterpret_cast<char*>(buffer.data()), cap_len);
}

void printPacket(const Packet &packet) 
{
    // 构建JSON对象
    rapidjson::Document pktObj;
    rapidjson::Document::AllocatorType& allocator = pktObj.GetAllocator();

    pktObj.SetObject();
    pktObj.AddMember("frame_number", packet.frame_number, allocator);
    pktObj.AddMember("timestamp", rapidjson::Value(packet.time.c_str(), allocator), allocator);
    pktObj.AddMember("src_ip", rapidjson::Value(packet.src_ip.c_str(), allocator), allocator);
    pktObj.AddMember("src_addr", rapidjson::Value(packet.src_addr.c_str(), allocator), allocator);
    pktObj.AddMember("src_port", rapidjson::Value(packet.src_port.c_str(), allocator), allocator);
    pktObj.AddMember("dst_ip", rapidjson::Value(packet.dst_ip.c_str(), allocator), allocator);
    pktObj.AddMember("dst_addr", rapidjson::Value(packet.dst_addr.c_str(), allocator), allocator);
    pktObj.AddMember("dst_port", rapidjson::Value(packet.dst_port.c_str(), allocator), allocator);
    pktObj.AddMember("protocol", rapidjson::Value(packet.protocol.empty() ? "(unkonw)" : packet.protocol.c_str(), allocator), allocator);
    pktObj.AddMember("info", rapidjson::Value(packet.info.empty() ? "(unkonw)" : packet.info.c_str(), allocator), allocator);
    pktObj.AddMember("file_offset", packet.file_offset, allocator);
    pktObj.AddMember("cap_len", packet.cap_len, allocator);

    // 序列化为 JSON 字符串
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    pktObj.Accept(writer);

    LOG_F(INFO, buffer.GetString());
}

void exec(const char* cmd, const std::string& packet_file)
{
    std::array<char, 128> buffer;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    std::vector<Packet> packets;

    if(!pipe)
    {
        LOG_F(ERROR,"Failed to run tshark command : %s", cmd);
    }

    uint32_t file_offset = sizeof(PcapHeader);
    while (fgets(buffer.data(), sizeof(buffer), pipe.get()) != nullptr) {
        Packet packet;
        if(parseLine(buffer.data(), packet)){
            // 计算当前报文的偏移，然后记录在Packet对象中
            packet.file_offset = file_offset + sizeof(PacketHeader);

            // 更新偏移游标
            file_offset = file_offset + sizeof(PacketHeader) + packet.cap_len;
            packets.push_back(packet);
        }else{
            LOG_F(WARNING, "Failed to parse line: %s", buffer.data());
            continue;
        }
    }

    for (auto &p : packets) {
        printPacket(p);

        // 读取这个报文的原始十六进制数据
        std::vector<unsigned char> buffer;
        readPacketHex(packet_file, p.file_offset, p.cap_len, buffer);
        
        // 打印读取到的数据：
        std::ostringstream hexStream;  // 使用字符串流拼接十六进制数据
        hexStream << "Packet Hex: ";
        for (unsigned char byte : buffer) {
            hexStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
        }

        LOG_F(INFO, "%s", hexStream.str().c_str());
    }
}

int main(int argc, char* argv[])
{   
    std::array<char, 128> buffer;
    std::string packet_file = "/home/capture.pcap";
    std::string ts = get_timestamp();
    std::string log_name = "logs/log_" + ts + ".txt";

    loguru::init(argc, argv);
    loguru::add_file(log_name.c_str(), loguru::Truncate, loguru::Verbosity_MAX);

    const char* cmd = "/usr/bin/tshark -r /home/capture.pcap -T fields -e frame.number -e frame.time -e frame.cap_len -e ip.src -e ipv6.src -e ip.dst -e ipv6.dst -e tcp.srcport -e udp.srcport -e tcp.dstport -e udp.dstport -e _ws.col.Protocol -e _ws.col.Info";

    exec(cmd, packet_file);
    return 0;
}