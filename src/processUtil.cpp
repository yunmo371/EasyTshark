#include "processUtil.hpp"
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

bool ProcessUtil::Exec(const char* command)
{
    int result = system(command);
    return result == 0;
}

FILE* ProcessUtil::PopenEx(const char* command, pid_t* pid, const char* type)
{
    int pipefd[2];
    pid_t childpid;

    if (pipe(pipefd) < 0)
        return nullptr;

    childpid = fork();

    if (childpid < 0)
    {
        close(pipefd[0]);
        close(pipefd[1]);
        return nullptr;
    }

    if (childpid == 0)
    { // 子进程
        if (type[0] == 'r')
        {
            close(pipefd[0]);
            dup2(pipefd[1], STDOUT_FILENO);
        }
        else
        {
            close(pipefd[1]);
            dup2(pipefd[0], STDIN_FILENO);
        }

        execl("/bin/sh", "sh", "-c", command, nullptr);
        _exit(127);
    }

    // 父进程
    if (pid)
        *pid = childpid;

    if (type[0] == 'r')
    {
        close(pipefd[1]);
        return fdopen(pipefd[0], "r");
    }
    else
    {
        close(pipefd[0]);
        return fdopen(pipefd[1], "w");
    }
}

bool ProcessUtil::Kill(pid_t pid)
{
    if (pid <= 0)
        return false;

    if (kill(pid, SIGTERM) != 0)
        return false;

    int status;
    if (waitpid(pid, &status, 0) != pid)
        return false;

    return true;
} 