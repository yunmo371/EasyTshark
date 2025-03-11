#include <iomanip>
#include <array>

#include "loguru.hpp"
#include "utils.hpp"
#include "tsharkManager.hpp"

void convertXmlNodeToJson(rapidxml::xml_node<>* xmlNode, rapidjson::Value& jsonNode, rapidjson::Document::AllocatorType& allocator) {
    // 处理节点的属性
    for (rapidxml::xml_attribute<>* attr = xmlNode->first_attribute(); attr; attr = attr->next_attribute()) {
        jsonNode.AddMember(rapidjson::Value(attr->name(), allocator), rapidjson::Value(attr->value(), allocator), allocator);
    }

    // 处理子节点
    bool hasChildNodes = false;
    for (rapidxml::xml_node<>* child = xmlNode->first_node(); child; child = child->next_sibling()) {
        hasChildNodes = true;
        rapidjson::Value childJson(rapidjson::kObjectType);
        convertXmlNodeToJson(child, childJson, allocator);
        jsonNode.AddMember(rapidjson::Value(child->name(), allocator), childJson, allocator);
    }

    // 如果没有子节点，处理文本内容
    if (!hasChildNodes && xmlNode->value_size() > 0) {
        jsonNode.SetString(xmlNode->value(), allocator); // 修正：传递 Allocator
    }
}

int main(int argc, char *argv[])
{


    // TsharkManager tsharkManager("/root/dev/learn_from_xuanyuan/output");
    // std::string ts = CommonUtil::get_timestamp();
    // std::string capture_log_name = "logs/catch_log_" + ts + ".txt";
    // // std::string capture_log_name  = "logs/log_" + ts + ".txt";
    // loguru::init(argc, argv);
    // loguru::add_file(capture_log_name.c_str(), loguru::Append, loguru::Verbosity_MAX);

    // // 启动监控
    // tsharkManager.startMonitorAdaptersFlowTrend();

    // // 睡眠10秒，等待监控网卡数据
    // std::this_thread::sleep_for(std::chrono::seconds(10));

    // // 读取监控到的数据
    // std::map<std::string, std::map<long, long>> trendData;
    // tsharkManager.getAdaptersFlowTrendData(trendData);

    // // 停止监控
    // tsharkManager.stopMonitorAdaptersFlowTrend();

    // // 把获取到的数据打印输出
    // rapidjson::Document resDoc;
    // rapidjson::Document::AllocatorType &allocator = resDoc.GetAllocator();
    // resDoc.SetObject();
    // rapidjson::Value dataObject(rapidjson::kObjectType);
    // for (const auto &adaptorItem : trendData)
    // {
    //     rapidjson::Value adaptorDataList(rapidjson::kArrayType);
    //     for (const auto &timeItem : adaptorItem.second)
    //     {
    //         rapidjson::Value timeObj(rapidjson::kObjectType);
    //         timeObj.AddMember("time", (unsigned int)timeItem.first, allocator);
    //         timeObj.AddMember("bytes", (unsigned int)timeItem.second, allocator);
    //         adaptorDataList.PushBack(timeObj, allocator);
    //     }

    //     dataObject.AddMember(rapidjson::StringRef(adaptorItem.first.c_str()), adaptorDataList, allocator);
    // }

    // resDoc.AddMember("data", dataObject, allocator);

    // // 序列化为 JSON 字符串
    // rapidjson::StringBuffer buffer;
    // rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    // resDoc.Accept(writer);

    // LOG_F(INFO, "网卡流量监控数据: %s", buffer.GetString());


    // 读取xml文件并转换
    std::ifstream xmlFile("/home/packets.xml");
    std::string xmlContent((std::istreambuf_iterator<char>(xmlFile)), std::istreambuf_iterator<char>());
    xmlFile.close();

    // 使用 RapidXML 解析 XML
    rapidxml::xml_document<> doc;
    doc.parse<0>(&xmlContent[0]);

    // 创建 JSON 文档并转换
    rapidjson::Document jsonDoc;
    jsonDoc.SetObject();
    rapidjson::Document::AllocatorType& jsonAllocator = jsonDoc.GetAllocator(); // 重命名变量，避免冲突

    // 转换根节点
    convertXmlNodeToJson(doc.first_node(), jsonDoc, jsonAllocator);

    // 序列化 JSON 数据
    rapidjson::StringBuffer jsonBuffer; // 重命名变量，避免冲突
    rapidjson::PrettyWriter<rapidjson::StringBuffer> jsonWriter(jsonBuffer); // 重命名变量，避免冲突
    jsonDoc.Accept(jsonWriter);

    // 保存 JSON 文件
    std::ofstream jsonFile("output.json");
    jsonFile << jsonBuffer.GetString();
    jsonFile.close();

    std::cout << "XML 文件已成功转换为 JSON 文件并保存到 output.json" << std::endl;

    
    // // 抓包
    // tsharkManager.startCapture("eth0");
    // std::string input;
    // while (true)
    // {
    //     std::cout << "请输入q退出抓包: ";
    //     std::cin >> input;
    //     if (input == "q")
    //     {
    //         tsharkManager.stopCapture();
    //         break;
    //     }
    // }
    // // 解包
    // std::string analysis_log_name = "logs/analysis_log_" + ts + ".txt";
    // loguru::add_file(analysis_log_name.c_str(), loguru::Append, loguru::Verbosity_MAX);
    // tsharkManager.analysisFile("capture.pcap");
    // tsharkManager.printAllPackets();

    // std::vector<AdapterInfo> adaptors = tsharkManager.getNetworkAdapterInfo();
    // for (auto item : adaptors)
    // {
    //     LOG_F(INFO, "网卡[%d]: name[%s] remark[%s]", item.id, item.name.c_str(), item.remark.c_str());
    // }
    return 0;
}
