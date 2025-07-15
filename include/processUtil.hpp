#ifndef processUtil_hpp
#define processUtil_hpp

#include <cstdio>
#include <string>
#include <sys/types.h>

/**
 * @brief 进程操作工具类
 */
class ProcessUtil {
public:
    /**
     * @brief 执行命令并等待完成
     * @param command 要执行的命令
     * @return true 执行成功
     * @return false 执行失败
     */
    static bool Exec(const char* command);

    /**
     * @brief 扩展的 popen 函数，返回进程 ID
     * @param command 要执行的命令
     * @param pid 输出参数，存储子进程的 PID
     * @param type 打开模式 ("r" 或 "w")，默认为 "r"
     * @return FILE* 管道文件指针
     */
    static FILE* PopenEx(const char* command, pid_t* pid, const char* type = "r");

    /**
     * @brief 终止指定 PID 的进程
     * @param pid 进程 ID
     * @return true 终止成功
     * @return false 终止失败
     */
    static bool Kill(pid_t pid);
};

#endif 