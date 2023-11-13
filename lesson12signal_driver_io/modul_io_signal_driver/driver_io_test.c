#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <poll.h>
#include <signal.h>

#include <errno.h>

int fd = -1;

void handler(int sig)//信号处理函数，与signal绑定的
{
    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN,
    };

    int ret = poll(&pfd, 1, ~0);//监控pfd，最大文件描述符1，永不超时
    if(0 >= ret){               //没一个就绪则阻塞，只要其中有任意一个就绪就往下走
        perror("poll");
        return;
    }

#define MAX 1024
    char buf[MAX];
    memset(buf, 0, MAX); 
    if(0 > read(fd, buf, MAX)){
        perror("read");
    }else{
        printf("RD: %s\n", buf);
    }
}

int main(int num, char *argv[])
{
    if(2 != num){
        printf("Usage: %s /dev/devfile\n", argv[0]);
        return -1;
    }

    fd = open(argv[1], O_RDWR|O_NONBLOCK);
    if(0 > fd){
        printf("pid = %d, %s\n", getpid(), (char *)strerror(errno));
        return -1;
    }

    signal(SIGIO, handler);//绑定信号处理函数

    fcntl(fd, F_SETOWN, getpid());//关联收发，设置对应文件的拥有者是本进程，这样接下来才能进行信号的收发

    int flag = fcntl(fd, F_GETFL);//读取对应文件描述符上的flg信息
    flag  |= O_ASYNC;
    fcntl(fd, F_SETFL, flag);     //设置对应文件描述符上的flg信息,使其支持异步通知
                                  //这个函数实质上最终调用的是操作方法集中的.fasync标准接口，对应到驱动层中的相应函数
    while(1){
        printf("---------w: 1----------\n");
    #define MAX 1024
        char buf[MAX];
        fgets(buf, MAX, stdin);         
        write(fd, buf, strlen(buf));
    }

    close(fd);

    return 0;
}