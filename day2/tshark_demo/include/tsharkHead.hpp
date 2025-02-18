#ifndef tsharkHead_hpp
#define tsharkHead_hpp

#include<string>

struct Packet {
    int frame_number;			// 数据包编号
    std::string time;			// 数据包的时间戳
    std::string src_ip;			// 源IP地址
    std::string dst_ip;			// 目的IP地址
    std::string protocol;		// 协议
    std::string info;			// 数据包的概要信息
};

#endif