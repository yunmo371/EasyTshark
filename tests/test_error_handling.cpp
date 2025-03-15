#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "tsharkManager.hpp"

// 测试辅助函数
namespace
{
    // 检查文件是否存在
    bool fileExists(const std::string& filename)
    {
        struct stat buffer;
        return (stat(filename.c_str(), &buffer) == 0);
    }

    // 创建目录
    bool createDirectory(const std::string& dirName)
    {
        return mkdir(dirName.c_str(), 0755) == 0 || errno == EEXIST;
    }

    // 递归删除目录
    void removeDirectory(const std::string& dirName)
    {
        std::string cmd = "rm -rf " + dirName;
        system(cmd.c_str());
    }
} // namespace

// 测试类
class ErrorHandlingTest : public ::testing::Test
{
protected:
    std::string    testDir;
    TsharkManager* tsharkManager;

    void SetUp() override
    {
        testDir = "test_error_handling";
        createDirectory(testDir);
        tsharkManager = new TsharkManager("/root/dev/learn_from_xuanyuan/output");
    }

    void TearDown() override
    {
        removeDirectory(testDir);
        delete tsharkManager;
    }
};

// 测试非法XML文件转换
TEST_F(ErrorHandlingTest, ConvertInvalidXmlToJson)
{
    // 创建一个无效的XML文件
    std::string invalidXmlFile = testDir + "/invalid.xml";
    std::string jsonFile       = testDir + "/output.json";

    // 写入无效的XML内容
    std::ofstream xmlFile(invalidXmlFile);
    xmlFile << "This is not a valid XML file";
    xmlFile.close();

    // 尝试转换
    bool result = tsharkManager->convertXmlToJson(invalidXmlFile, jsonFile);

    // 验证转换失败
    EXPECT_FALSE(result);
    // JSON文件可能已创建但应该为空或包含错误信息
    if (fileExists(jsonFile))
    {
        std::ifstream jsonFileStream(jsonFile);
        std::string   content((std::istreambuf_iterator<char>(jsonFileStream)),
                              std::istreambuf_iterator<char>());
        jsonFileStream.close();
        // 文件可能为空或包含错误信息
    }
}

// 测试不存在的XML文件转换
TEST_F(ErrorHandlingTest, ConvertNonExistentXmlToJson)
{
    std::string nonExistentFile = testDir + "/nonexistent.xml";
    std::string jsonFile        = testDir + "/output.json";

    // 确保文件不存在
    if (fileExists(nonExistentFile))
    {
        remove(nonExistentFile.c_str());
    }

    // 尝试转换
    bool result = tsharkManager->convertXmlToJson(nonExistentFile, jsonFile);

    // 验证转换失败
    EXPECT_FALSE(result);
}

// 测试无法写入的JSON文件路径
TEST_F(ErrorHandlingTest, ConvertXmlToUnwritableJson)
{
    // 创建一个有效的XML文件
    std::string   xmlFile = testDir + "/valid.xml";
    std::ofstream xmlFileStream(xmlFile);
    xmlFileStream << "<?xml version=\"1.0\"?><pdml><packet></packet></pdml>";
    xmlFileStream.close();

    // 使用一个无法写入的路径（例如，不存在的目录）
    std::string unwritableJsonFile = "/nonexistent_dir/output.json";

    // 尝试转换
    bool result = tsharkManager->convertXmlToJson(xmlFile, unwritableJsonFile);

    // 验证转换失败
    EXPECT_FALSE(result);
}

// 测试空XML文件转换
TEST_F(ErrorHandlingTest, ConvertEmptyXmlToJson)
{
    // 创建一个空的XML文件
    std::string emptyXmlFile = testDir + "/empty.xml";
    std::string jsonFile     = testDir + "/output.json";

    std::ofstream xmlFile(emptyXmlFile);
    xmlFile.close();

    // 尝试转换
    bool result = tsharkManager->convertXmlToJson(emptyXmlFile, jsonFile);

    // 验证转换失败
    EXPECT_FALSE(result);
}

// 测试PCAP到XML转换的错误处理
TEST_F(ErrorHandlingTest, ConvertNonExistentPcapToXml)
{
    std::string nonExistentPcapFile = testDir + "/nonexistent.pcap";
    std::string xmlFile             = testDir + "/output.xml";

    // 确保文件不存在
    if (fileExists(nonExistentPcapFile))
    {
        remove(nonExistentPcapFile.c_str());
    }

    // 尝试转换
    bool result = tsharkManager->convertPcapToXml(nonExistentPcapFile, xmlFile);

    // 验证转换失败
    EXPECT_FALSE(result);
}