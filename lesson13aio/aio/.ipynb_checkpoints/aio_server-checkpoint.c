#include <stdio.h>  
#include <stdlib.h>  
#include <errno.h>  
#include <string.h>  
#include <netinet/in.h>  
#include <sys/socket.h>  
#include <unistd.h>  
#include <fcntl.h>  
#include <aio.h>  
#include <pthread.h>  
#include <arpa/inet.h>
#include <sys/types.h>
#include <signal.h>

#define BUF_SIZE 1024 

void aio_completion_handler(sigval_t sigval);

void setup_ios(int fd, struct aiocb my_aiocb)
{
    //初始化AIO请求  
    bzero((char *)& my_aiocb, sizeof(struct aiocb));
    my_aiocb.aio_fildes = fd;
    my_aiocb.aio_buf = malloc(BUF_SIZE + 1);
    my_aiocb.aio_nbytes = BUF_SIZE;
    my_aiocb.aio_offset = 0;

    //设置线程回调函数  
    my_aiocb.aio_sigevent.sigev_notify = SIGEV_THREAD;
    my_aiocb.aio_sigevent.sigev_notify_function = aio_completion_handler;
    my_aiocb.aio_sigevent.sigev_notify_attributes = NULL;
    my_aiocb.aio_sigevent.sigev_value.sival_ptr = &my_aiocb;
}

//回调函数  
void aio_completion_handler(sigval_t sigval)
{
    struct aiocb *req;
    int ret;
   
    req = (struct aiocb *)sigval.sival_ptr;
    printf("aio_error(req)=%d\n",aio_error(req));
    printf("aio_return(req)=%ld\n",aio_return(req));
    if (aio_error(req) == 0)
    {
        if ((ret = aio_return(req)) > 0)
        {
            printf("Thread id %u recv:%s\n", (unsigned int)pthread_self(), (char*)req->aio_buf);
        }
    }

    char* buf = (char*)req->aio_buf;

    if (send(req->aio_fildes, buf, strlen(buf), 0) == -1)
    {
        perror("send");
        return;
    }

    close(req->aio_fildes);

    return;
}

int main()
{
    int sockfd;
    int sin_size;
    struct sockaddr_in addr, cliaddr;

    //创建socket  
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("createSocket");
        return -1;
    }

    //初始化socket结构  
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8888);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    //绑定套接口  
    if (bind(sockfd, (struct sockaddr *) &addr, sizeof(struct sockaddr)) == -1)
    {
        perror("bind");
        return -1;
    }

    //创建监听套接口  
    if (listen(sockfd, 10) == -1)
    {
        perror("listen");
        return -1;
    }

    printf("server is running! \n");

    
    //等待连接  
    while (1)
    {
        struct aiocb my_aiocb;

        struct sockaddr_in client_addr;
        socklen_t cliaddr_len = sizeof(client_addr);
        int NewClient = accept(sockfd, (struct sockaddr*)&client_addr, &cliaddr_len);
        if (NewClient < 0)
        {
            perror("accept");
            continue;
        }
        char cli_ip[INET_ADDRSTRLEN] = "";
        inet_ntop(AF_INET, &client_addr.sin_addr, cli_ip, INET_ADDRSTRLEN);
        printf("client ip = %s\n", cli_ip);
        
        //setup_io(NewClient, my_aiocb);
        
    bzero((char *)& my_aiocb, sizeof(struct aiocb));
    my_aiocb.aio_fildes = NewClient;
    my_aiocb.aio_buf = malloc(BUF_SIZE + 1);
    my_aiocb.aio_nbytes = BUF_SIZE;
    my_aiocb.aio_offset = 0;

    //设置线程回调函数  
    my_aiocb.aio_sigevent.sigev_notify = SIGEV_THREAD;
    my_aiocb.aio_sigevent.sigev_notify_function = aio_completion_handler;
    my_aiocb.aio_sigevent.sigev_notify_attributes = NULL;
    my_aiocb.aio_sigevent.sigev_value.sival_ptr = &my_aiocb;
        
        aio_read(&my_aiocb);
    }
    close(sockfd);
}