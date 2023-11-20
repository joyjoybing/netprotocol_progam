#include  <unistd.h>
#include  <sys/types.h>       /* basic system data types */
#include  <sys/socket.h>      /* basic socket definitions */
#include  <netinet/in.h>      /* sockaddr_in{} and other Internet defns */
#include  <arpa/inet.h>       /* inet(3) functions */
#include <sys/select.h>       /* select function*/

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#define MAXLINE 10240
#define max(a,b)    ((a) > (b) ? (a) : (b))
//typedef struct sockaddr  SA;

void handle(int sockfd);

int main(int argc, char **argv)
{
    char * servInetAddr = "127.0.0.1";
    int servPort = 6888;
    char buf[MAXLINE];
    int connfd;
    struct sockaddr_in servaddr;

    if (argc == 2) {
        servInetAddr = argv[1];
    }
    if (argc == 3) {
        servInetAddr = argv[1];
        servPort = atoi(argv[2]);
    }
    if (argc > 3) {
        printf("usage: selectechoclient <IPaddress> <Port>\n");
        return -1;
    }

    connfd = socket(AF_INET, SOCK_STREAM, 0);

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(servPort);
    inet_pton(AF_INET, servInetAddr, &servaddr.sin_addr);

    if (connect(connfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
        perror("connect error");
        return -1;
    }
    printf("welcome to selectechoclient\n");
    handle(connfd);     /* do it all */
    close(connfd);
    printf("exit\n");
    exit(0);
}


void handle(int connfd)
{
    FILE* fp = stdin;
    char sendline[MAXLINE], recvline[MAXLINE];
    fd_set rset;
    FD_ZERO(&rset);
    int maxfds = max(fileno(fp), connfd) + 1;
    int nread;
    for (;;) {
        FD_SET(fileno(fp), &rset);
        FD_SET(connfd, &rset);

        if (select(maxfds, &rset, NULL, NULL, NULL) == -1) {
            perror("select error");
            continue;
        }

        if (FD_ISSET(connfd, &rset)) {
            //接收到服务器响应
            nread = read(connfd, recvline, MAXLINE);
            if (nread == 0) {
                printf("server close the connection\n");
                break;
            }
            else if (nread == -1) {
                perror("read error");
                break;
            }
            else {
                //server response
                write(STDOUT_FILENO, recvline, nread);
            }
        }

        if (FD_ISSET(fileno(fp), &rset)) {
            //标准输入可读
            if (fgets(sendline, MAXLINE, fp) == NULL) {
                //eof exit
                break;
            }
            else {
                write(connfd, sendline, strlen(sendline));
            }
        }

    }
}
