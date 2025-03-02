#ifndef tsharkManager_hpp
#define tsharkManager_hpp

#include"tsharkDataType.hpp"
#include"rapidjson/document.h"
#include"rapidjson/writer.h"
#include"rapidjson/prettywriter.h"
#include"rapidjson/stringbuffer.h"

#include<cstdio>
#include<cstdlib>
#include<cstring>
#include<vector>
#include<sstream>
#include<iostream>
#include<fstream>
#include<unordered_map>

class TsharkManager {
public:
    TsharkManager(std::string currentFilePath);
    ~TsharkManager();

    // 分析数据包文件
    bool analysisFile(std::string filePath);
    // 打印所有数据包的信息
    void printAllPackets();
    // 获取指定编号数据包的十六进制数据
    bool getPacketHexData(uint32_t frameNumber, std::vector<unsigned char> &data);

private:
    bool parseLine(std::string line, std::shared_ptr<Packet> packet);

private:
    std::string tsharkPath;

    // 当前分析的文件路径
    std::string currentFilePath;

    // 分析得到的所有数据包信息，key是数据包ID，value是数据包信息指针，方便根据编号获取指定数据包信息
    std::unordered_map<uint32_t, std::shared_ptr<Packet>> allPackets;
};


#endif