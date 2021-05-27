/*
@文件:write.c
@作者: CSHF[https://github.com/CSHF-yhhhh]
@说明: 驱动相关函数
*/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

//打开设备驱动,如:/dev/cshfFirewall
int OpenDev(char *name)
{
    printf("%s\n", name);
    int fd = open(name, O_RDWR);
    if (fd < 0)
        return -1;
    return fd;
}
//向驱动中写信息
int WriteDev(int fd, char *msg)
{
    int ret = write(fd, msg, strlen(msg));
    if (ret < 0)
    {
        perror("Failed to write the message to the device.");
        return errno;
    }
    return ret;
}
//关闭驱动
int CloseDev(int fd)
{
    close(fd);
    return 1;
}