#include<iomanip>

#include"utils.hpp"
#include"loguru.hpp"
#include"tsharkManager.hpp"

TsharkManager::TsharkManager(std::string currentFilePath){
    tsharkPath = "/usr/bin/tshark";
}


TsharkManager::~TsharkManager(){}


bool TsharkManager::getPacketHexData(uint32_t frameNumber, std::vector<unsigned char> &buffer){
    if(frameNumber >= allPackets.size()){
        return false;
    }
    std::ifstream file(currentFilePath, std::ios::binary);
    if(!file)
    {
        LOG_F(ERROR, "packet_file open failed");
    }
    if(file.fail())
    {
        LOG_F(ERROR, "not found location");
    }
    if(allPackets.find(frameNumber) != allPackets.end()){
        std::shared_ptr<Packet> packet = allPackets[frameNumber];
        uint32_t cap_len = packet->cap_len;
        buffer.resize(cap_len);
        file.read(reinterpret_cast<char*>(buffer.data()), cap_len);
        return true;
    }
    LOG_F(ERROR, "ERROR!");
    return false;
}


bool TsharkManager::analysisFile(std::string filePath){
    std::vector<std::string> tsharkArgs = {
        tsharkPath,
        "-r", filePath,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "frame.cap_len",
        "-e", "eth.src",
        "-e", "eth.dst",
        "-e", "ip.src",
        "-e", "ipv6.src",
        "-e", "ip.dst",
        "-e", "ipv6.dst",
        "-e", "tcp.srcport",
        "-e", "udp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
    };

    
    std::string cmd;
    for(const auto& arg : tsharkArgs){
        cmd += arg + " ";
    }

    // int result = std::system(cmd.c_str());

    FILE* pipe = popen(cmd.c_str(), "r");
    if(!pipe){
        std::cerr << "Failed to run tshark command!" << std::endl;
        return false;
    }

    char buffer[4096];

    // 当前处理的报文在文件中的偏移，第一个报文的偏移就是全局文件头24(也就是sizeof(PcapHeader))字节
    uint32_t file_offset = sizeof(PcapHeader);
    while(fgets(buffer, sizeof(buffer), pipe) != nullptr){
        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        if(!parseLine(buffer, packet)){
            LOG_F(ERROR, buffer);
            assert(false);
        }

        // 计算当前报文的偏移，然后记录在Packet对象中
        packet->file_offset = file_offset + sizeof(PacketHeader);

        // 更新偏移游标
        file_offset = file_offset + sizeof(PacketHeader) + packet->cap_len;

        // 获取IP地理位置
        packet->src_location = IP2RegionUtil::getIpLocation(packet->src_ip);
        packet->dst_location = IP2RegionUtil::getIpLocation(packet->dst_ip);
    
        // 将分析的数据包插入保存起来
        allPackets.insert(std::make_pair<>(packet->frame_number, packet));
    }
    pclose(pipe);

    // 记录当前分析的文件路径
    currentFilePath = filePath;

    return true;
}


bool TsharkManager::parseLine(std::string line, std::shared_ptr<Packet> packet){
    // line = UTF8ToANSIString(line);
    if (line.back() == '\n') {
        line.pop_back();
    }
    std::stringstream ss(line);
    std::string field;
    std::vector<std::string> fields;

    // 自己实现字符串拆分
    size_t start = 0, end;
    while((end = line.find('\t', start)) != std::string::npos){
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(line.substr(start)); 
    
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

    IP2RegionUtil ip2RegionUtil;
    ip2RegionUtil.init("/home/ip2region.xdb");

    if (fields.size() >= 16) {
        packet->frame_number = std::stoi(fields[0]);
        packet->time = fields[1];
        packet->len = std::stoi(fields[2]);
        packet->cap_len = std::stoi(fields[3]);
        packet->src_mac = fields[4];
        packet->dst_mac = fields[5];
        packet->src_ip = fields[6].empty() ? fields[7] : fields[6];
        packet->dst_ip = fields[8].empty() ? fields[9] : fields[8];
        if (!fields[10].empty() || !fields[11].empty()) {
            packet->src_port = std::stoi(fields[10].empty() ? fields[11] : fields[10]);
        }
        if (!fields[12].empty() || !fields[13].empty()) {
            packet->dst_port = std::stoi(fields[12].empty() ? fields[13] : fields[12]);
        }
        packet->protocol = fields[14];
        packet->info = fields[12];
        return true;
    }else{
        return false;
    }
}


void TsharkManager::printAllPackets(){
    uint32_t count = 0;
    for(auto pair : allPackets){
        std::shared_ptr<Packet> packet = pair.second;
        count ++;
        // 构建JSON对象
        rapidjson::Document pktObj;
        rapidjson::Document::AllocatorType& allocator = pktObj.GetAllocator();
        pktObj.SetObject();

        pktObj.AddMember("frame_number", packet->frame_number, allocator);
        pktObj.AddMember("timestamp", rapidjson::Value(packet->time.c_str(), allocator), allocator);
        pktObj.AddMember("src_mac", rapidjson::Value(packet->src_mac.c_str(), allocator), allocator);
        pktObj.AddMember("src_ip", rapidjson::Value(packet->src_ip.c_str(), allocator), allocator);
        pktObj.AddMember("src_location", rapidjson::Value(packet->src_location.c_str(), allocator), allocator);
        pktObj.AddMember("src_port", packet->src_port, allocator);
        pktObj.AddMember("dst_ip", rapidjson::Value(packet->dst_ip.c_str(), allocator), allocator);
        pktObj.AddMember("dst_location", rapidjson::Value(packet->dst_location.c_str(), allocator), allocator);
        pktObj.AddMember("dst_port", packet->dst_port, allocator);
        pktObj.AddMember("protocol", rapidjson::Value(packet->protocol.c_str(), allocator), allocator);
        pktObj.AddMember("info", rapidjson::Value(packet->info.c_str(), allocator), allocator);
        pktObj.AddMember("file_offset", packet->file_offset, allocator);
        pktObj.AddMember("cap_len", packet->cap_len, allocator);
        pktObj.AddMember("len", packet->len, allocator);

        // 序列化为 JSON 字符串
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        pktObj.Accept(writer);


        LOG_F(INFO, buffer.GetString());
        std::vector<unsigned char> buffer2(packet->cap_len);
        getPacketHexData(packet->frame_number, buffer2);
        std::stringstream hex_str;
        hex_str << "Packet Hex: ";
        for(unsigned char byte : buffer2)
            hex_str << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte) << " ";
        LOG_F(INFO, "%s\n", hex_str.str().c_str());
    }
    LOG_F(INFO, "Number of packets: %zu", count);
}
