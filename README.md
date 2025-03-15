# 网络数据包捕获与分析工具

本项目是一个基于C++实现的网络数据包捕获与分析工具，可以实时抓取网络数据包，并将其转换为XML和JSON格式进行分析。

## 功能特点

1. 实时网络数据包捕获：可以指定网卡和捕获时间
2. 数据包格式转换：将捕获的数据包转换为XML和JSON格式
3. 跨平台支持：支持Linux、Windows和macOS系统
4. 模块化设计：数据捕获和转换功能封装在独立的类中
5. 完善的错误处理：对各种异常情况进行处理
6. 全面的单元测试：确保代码质量和稳定性

## 环境要求

- C++11兼容的编译器（GCC 4.8+, Clang 3.3+, MSVC 2015+）
- CMake 3.10+
- Wireshark/tshark（用于数据包捕获和解析）

## 编译与安装

### 使用脚本构建

项目提供了便捷的构建脚本，支持多种选项：

```bash
# 默认构建（清理构建目录，编译项目，运行测试并忽略测试失败）
./run.sh

# 不清理构建目录
./run.sh --no-clean

# 不运行测试
./run.sh --no-test

# 严格测试模式（测试失败时退出）
./run.sh --strict-test

# 运行特定测试
./run.sh --test=TsharkManagerTest.ConvertXmlToJson

# 查看帮助信息
./run.sh --help
```

### 手动构建

```bash
mkdir -p build
cd build
cmake ..
make
```

### 依赖管理

本项目使用以下第三方库：

- RapidXML：用于XML解析
- RapidJSON：用于JSON处理
- loguru：用于日志记录
- GoogleTest：用于单元测试（构建时自动下载）

除GoogleTest外，这些依赖已包含在项目源码中，无需额外安装。

## 使用方法

1. 运行程序：

```bash
./output/tshark_demo_main
```

2. 按照提示选择网卡和捕获时间
3. 程序会自动捕获数据包，并将结果保存在data目录下：
   - data/packets.xml：XML格式的数据包内容
   - data/packets.json：JSON格式的数据包内容

## 单元测试

本项目使用GoogleTest框架进行单元测试。测试用例位于`tests`目录下。

### 运行单元测试

```bash
# 使用脚本运行所有测试
./run.sh --test

# 运行特定测试
./run.sh --test=DataConversionTest.ConvertXmlToJson

# 直接运行测试可执行文件
./output/unit_tests
```

### 测试覆盖范围

当前的单元测试覆盖以下组件：

- TsharkManager：测试基本功能和网络适配器信息获取
- DataConversion：测试数据格式转换功能
- ErrorHandling：测试错误处理和边界情况
- Performance：测试性能和稳定性（默认禁用）
- CommonUtil：测试时间戳和当前时间获取功能
- ProcessUtil：测试进程执行和管理功能

## 开发者指南

### IDE配置

项目包含VSCode配置文件，位于`.vscode`目录下：
- `c_cpp_properties.json`：配置C/C++扩展，包括头文件路径和编译器设置

### 代码规范

本项目使用clang-format进行代码格式化，规范定义在`.clang-format`文件中。主要规范包括：

- 缩进：使用4个空格
- 大括号风格：Allman风格（大括号独占一行）
- 指针和引用对齐：左对齐
- 命名空间缩进：所有命名空间内容都缩进
- 行长度限制：100个字符

### 安装和使用clang-format

#### 安装clang-format

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install clang-format

# CentOS/RHEL
sudo yum install clang-tools-extra

# macOS (使用Homebrew)
brew install clang-format

# Windows
# 可以通过LLVM安装程序或Visual Studio扩展安装
```

#### 格式化代码

可以使用以下命令格式化代码：

```bash
# 格式化单个文件
clang-format -i path/to/file.cpp

# 格式化所有C++源文件和头文件
find . -name "*.cpp" -o -name "*.hpp" | xargs clang-format -i

# 使用特定版本的clang-format（如果系统上安装了多个版本）
clang-format-10 -i path/to/file.cpp
```

#### 在VSCode中使用clang-format

1. 安装C/C++扩展
2. 在设置中启用格式化：
   ```json
   "C_Cpp.formatting": "clangFormat",
   "editor.formatOnSave": true
   ```
3. 使用快捷键格式化代码：`Shift+Alt+F`（Windows/Linux）或`Shift+Option+F`（macOS）

## 项目结构

```
.
├── CMakeLists.txt          # CMake构建配置
├── .clang-format           # 代码格式化规范
├── LICENSE                 # MIT许可证
├── run.sh                  # 构建和测试脚本
├── .vscode/                # VSCode配置文件
│   └── c_cpp_properties.json # C/C++扩展配置
├── include/                # 头文件目录
│   ├── tsharkDataType.hpp  # 数据类型定义
│   ├── tsharkManager.hpp   # 数据包管理器
│   └── utils.hpp           # 工具函数
├── src/                    # 源文件目录
│   ├── main.cpp            # 主程序入口
│   ├── tsharkManager.cpp   # 数据包管理器实现
│   └── utils.cpp           # 工具函数实现
├── tests/                  # 单元测试目录
│   ├── CMakeLists.txt      # 测试构建配置
│   ├── test_tsharkManager.cpp # 基本功能测试
│   ├── test_data_conversion.cpp # 数据转换测试
│   ├── test_error_handling.cpp # 错误处理测试
│   ├── test_performance.cpp # 性能测试
│   └── test_utils.cpp      # 工具函数测试
├── data/                   # 数据输出目录
│   ├── packets.xml         # XML格式的数据包
│   └── packets.json        # JSON格式的数据包
└── logs/                   # 日志目录
```

## 贡献指南

欢迎贡献代码、报告问题或提出改进建议。请遵循以下步骤：

1. Fork本仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建Pull Request

## 许可证

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

本项目采用MIT开源许可证，允许自由使用、修改和分发代码。使用本项目的代码时需满足：
- 在副本中保留原始版权声明
- 不得使用项目作者的名义进行背书

完整条款请参见[LICENSE文件](./LICENSE)。