#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdexcept>
#include <csignal>
#include <iomanip>
#include <set>

#include "utils.hpp"
#include "loguru.hpp"
#include "tsharkManager.hpp"

TsharkManager::TsharkManager(std::string currentFilePath)
{
    tsharkPath = "/usr/bin/tshark";
}

TsharkManager::~TsharkManager() {}

bool TsharkManager::getPacketHexData(uint32_t frameNumber, std::vector<unsigned char> &buffer)
{
    if (frameNumber >= allPackets.size())
    {
        return false;
    }
    std::ifstream file(currentFilePath, std::ios::binary);
    if (!file)
    {
        LOG_F(ERROR, "packet_file open failed");
    }
    if (file.fail())
    {
        LOG_F(ERROR, "not found location");
    }
    if (allPackets.find(frameNumber) != allPackets.end())
    {
        std::shared_ptr<Packet> packet = allPackets[frameNumber];
        uint32_t cap_len = packet->cap_len;
        buffer.resize(cap_len);
        file.read(reinterpret_cast<char *>(buffer.data()), cap_len);
        return true;
    }
    LOG_F(ERROR, "ERROR!");
    return false;
}

bool TsharkManager::analysisFile(std::string filePath)
{
    std::vector<std::string> tsharkArgs = {
        tsharkPath,
        "-r",
        filePath,
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "frame.time_epoch",
        "-e",
        "frame.len",
        "-e",
        "frame.cap_len",
        "-e",
        "eth.src",
        "-e",
        "eth.dst",
        "-e",
        "ip.src",
        "-e",
        "ipv6.src",
        "-e",
        "ip.dst",
        "-e",
        "ipv6.dst",
        "-e",
        "tcp.srcport",
        "-e",
        "udp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "udp.dstport",
        "-e",
        "_ws.col.Protocol",
        "-e",
        "_ws.col.Info",
    };

    std::string cmd;
    for (const auto &arg : tsharkArgs)
    {
        cmd += arg + " ";
    }

    // int result = std::system(cmd.c_str());

    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe)
    {
        std::cerr << "Failed to run tshark command!" << std::endl;
        return false;
    }

    char buffer[4096];

    // 当前处理的报文在文件中的偏移，第一个报文的偏移就是全局文件头24(也就是sizeof(PcapHeader))字节
    uint32_t file_offset = sizeof(PcapHeader);
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {
        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        if (!parseLine(buffer, packet))
        {
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

bool TsharkManager::parseLine(std::string line, std::shared_ptr<Packet> packet)
{
    // line = UTF8ToANSIString(line);
    if (line.back() == '\n')
    {
        line.pop_back();
    }
    std::stringstream ss(line);
    std::string field;
    std::vector<std::string> fields;

    // 自己实现字符串拆分
    size_t start = 0, end;
    while ((end = line.find('\t', start)) != std::string::npos)
    {
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

    if (fields.size() >= 16)
    {
        packet->frame_number = std::stoi(fields[0]);
        packet->time = fields[1];
        packet->len = std::stoi(fields[2]);
        packet->cap_len = std::stoi(fields[3]);
        packet->src_mac = fields[4];
        packet->dst_mac = fields[5];
        packet->src_ip = fields[6].empty() ? fields[7] : fields[6];
        packet->dst_ip = fields[8].empty() ? fields[9] : fields[8];
        if (!fields[10].empty() || !fields[11].empty())
        {
            packet->src_port = std::stoi(fields[10].empty() ? fields[11] : fields[10]);
        }
        if (!fields[12].empty() || !fields[13].empty())
        {
            packet->dst_port = std::stoi(fields[12].empty() ? fields[13] : fields[12]);
        }
        packet->protocol = fields[14];
        packet->info = fields[12];
        return true;
    }
    else
    {
        return false;
    }
}

std::vector<AdapterInfo> TsharkManager::getNetworkAdapterInfo()
{
    // 需要过滤掉的虚拟网卡
    std::set<std::string> specialInterfaces = {
        "sshdump", "ciscodump", "udpdump", "randdpkt"};
    std::vector<AdapterInfo> interfaces;
    char buffer[256] = {0};
    std::string result;

    std::string cmd = tsharkPath + " -D";
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe)
    {
        throw std::runtime_error("Failed to run tshark command!");
    }

    while (fgets(buffer, 256, pipe.get()) != nullptr)
    {
        result += buffer;
    }
    // 1.\Device\NPF_{xxxx} (网卡描述)
    std::istringstream stream(result);
    std::string line;
    int index = 1;
    while (std::getline(stream, line))
    {
        size_t startPos = line.find(". ") + 2;
        size_t endPos = line.find(" (", startPos);
        std::string interfaceName;
        std::string remark;
        if (endPos != std::string::npos) // 如果有描述
        {
            interfaceName = line.substr(startPos, endPos - startPos);
            remark = line.substr(endPos + 2, line.find(")", endPos) - endPos - 2);
        }
        else
        {
            interfaceName = line.substr(startPos);
        }

        // 滤掉特殊网卡
        if (specialInterfaces.find(interfaceName) != specialInterfaces.end())
        {
            continue;
        }
        AdapterInfo adapterInfo;
        adapterInfo.name = interfaceName;
        adapterInfo.id = index++;
        adapterInfo.remark = remark;

        interfaces.push_back(adapterInfo);
        {
            int endPos = line.find(' ', startPos + 1);
            std::string interfaceName;
            if (endPos != std::string::npos)
            {
                interfaceName = line.substr(startPos + 1, endPos - startPos - 1);
            }
            else
            {
                interfaceName = line.substr(startPos + 1);
            }

            // 滤掉特殊网卡
            if (specialInterfaces.find(interfaceName) != specialInterfaces.end())
            {
                continue;
            }

            AdapterInfo adapterInfo;
            adapterInfo.name = interfaceName;
            adapterInfo.id = index++;
            if (line.find("(") != std::string::npos && line.find(")") != std::string::npos)
            {
                adapterInfo.remark = line.substr(line.find("(") + 1, line.find(")") - line.find("(") - 1);
            }

            interfaces.push_back(adapterInfo);
        }
    }
    networkAdapters = interfaces;
    return interfaces;
}

void TsharkManager::printAllPackets()
{
    uint32_t count = 0;
    for (auto pair : allPackets)
    {
        std::shared_ptr<Packet> packet = pair.second;
        count++;
        // 构建JSON对象
        rapidjson::Document pktObj;
        rapidjson::Document::AllocatorType &allocator = pktObj.GetAllocator();
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

        // std::string srcMac = packet->src_mac;
        // std::string srcIp = packet->src_ip;
        // std::string adapterRemark = "unknown";
        // int adapterId = 0;
        // std::string adapterName = "unknown";
        // for (const auto &adapter : networkAdapters)
        // {
        //     if (adapter.name.find(srcMac) != std::string::npos || adapter.name.find(srcIp) != std::string::npos)
        //     {
        //         adapterId = adapter.id;
        //         adapterName = adapter.name;
        //         adapterRemark = adapter.remark;
        //         break;
        //     }
        // }
        // LOG_F(INFO, "网卡[%d]: name[%s] remark[%s]", adapterId, adapterName.c_str(), adapterRemark.c_str());

        std::vector<unsigned char> buffer2(packet->cap_len);
        getPacketHexData(packet->frame_number, buffer2);
        std::stringstream hex_str;
        hex_str << "Packet Hex: ";
        for (unsigned char byte : buffer2)
            hex_str << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte) << " ";
        LOG_F(INFO, "%s\n", hex_str.str().c_str());
    }
    LOG_F(INFO, "Number of packets: %zu", count);
}

bool TsharkManager::startCapture(std::string adapterName)
{
    LOG_F(INFO, "即将开始抓包，网卡：%s", adapterName.c_str());

    // 关闭停止标记
    stopFlag = false;

    // 启动抓包线程
    captureWorkThread = std::make_shared<std::thread>(&TsharkManager::captureWorkThreadEntry, this, "\"" + adapterName + "\"");

    return true;
}

bool TsharkManager::stopCapture()
{
    LOG_F(INFO, "即将停止抓包");
    stopFlag = true;

    if (captureWorkThread->joinable())
    {
        captureWorkThread->join();
    }

    return true;
}

void TsharkManager::captureWorkThreadEntry(std::string adapterName)
{
    try
    {
        std::string captureFile = "capture.pcap";
        std::vector<std::string> tsharkArgs = {
            tsharkPath,
            "-i",
            adapterName.c_str(),
            "-w",
            captureFile,
            "-F",
            "pcap",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "frame.time_epoch",
            "-e",
            "frame.len",
            "-e",
            "frame.cap_len",
            "-e",
            "eth.src",
            "-e",
            "eth.dst",
            "-e",
            "ip.src",
            "-e",
            "ipv6.src",
            "-e",
            "ip.dst",
            "-e",
            "ipv6.dst",
            "-e",
            "tcp.srcport",
            "-e",
            "udp.srcport",
            "-e",
            "tcp.dstport",
            "-e",
            "udp.dstport",
            "-e",
            "_ws.col.Protocol",
            "-e",
            "_ws.col.Info",
        };
        std::string command;
        for (const auto &arg : tsharkArgs)
        {
            command += arg + " ";
        }

        LOG_F(INFO, "Executing command: %s", command.c_str());
        FILE *pipe = popen(command.c_str(), "r");
        if (!pipe)
        {
            LOG_F(ERROR, "Failed to run tshark command!");
            return;
        }

        int pipe_fd = fileno(pipe);
        if (pipe_fd < 0)
        {
            LOG_F(ERROR, "Failed to get pipe file descriptor!");
            pclose(pipe);
            return;
        }
        // 设置为非阻塞模式
        int flags = fcntl(pipe_fd, F_GETFL, 0);
        fcntl(pipe_fd, F_SETFL, flags | O_NONBLOCK);

        // 创建 epoll 实例
        int epoll_fd = epoll_create1(0);
        if (epoll_fd < 0)
        {
            LOG_F(ERROR, "Failed to create epoll instance!");
            pclose(pipe);
            return;
        }

        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = pipe_fd;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pipe_fd, &ev) < 0)
        {
            LOG_F(ERROR, "Failed to add file descriptor to epoll!");
            close(epoll_fd);
            pclose(pipe);
            return;
        }

        char buffer[4096];
        uint32_t file_offset = sizeof(PcapHeader);

        while (!stopFlag)
        {
            struct epoll_event events[1];
            int nfds = epoll_wait(epoll_fd, events, 1, 1000);
            if (nfds > 0)
            {
                if (events[0].events & EPOLLIN)
                {
                    ssize_t bytes_read;
                    while ((bytes_read = read(pipe_fd, buffer, sizeof(buffer))) > 0)
                    {
                        std::string line(buffer, bytes_read);
                        LOG_F(INFO, "Read data: %s", line.c_str());
                    }
                    if (bytes_read == 0)
                    {
                        LOG_F(INFO, "Pipe closed by tshark.");
                        break;
                    }
                    else if (bytes_read < 0 && errno != EAGAIN)
                    {
                        LOG_F(ERROR, "Read error: %s", strerror(errno));
                        break;
                    }
                }
                if (events[0].events & EPOLLHUP)
                {
                    LOG_F(INFO, "Pipe closed by tshark.");
                    break;
                }
            }
            else if (nfds == 0)
            {
                LOG_F(INFO, "epoll_wait timed out.");
            }
            else
            {
                LOG_F(ERROR, "epoll_wait error: %s", strerror(errno));
                break;
            }
        }
        close(epoll_fd);
        pclose(pipe);
        LOG_F(INFO, "Capture thread exiting gracefully.");
    }
    catch (const std::exception &e)
    {
        LOG_F(ERROR, "Exception in captureWorkThreadEntry: %s", e.what());
    }
    catch (...)
    {
        LOG_F(ERROR, "Unknown exception in captureWorkThreadEntry.");
    }
}