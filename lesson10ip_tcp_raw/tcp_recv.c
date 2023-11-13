/**
 * @file ip_tcp_recv.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/* ip首部长度 */
#define IP_HEADER_LEN sizeof(struct ip)
/* tcp首部长度 */
#define TCP_HEADER_LEN sizeof(struct tcphdr)
/* ip首部 + tcp首部长度 */
#define IP_TCP_HEADER_LEN IP_HEADER_LEN + TCP_HEADER_LEN
/* 接收数据缓冲大小 */
#define BUFFER_SIZE 1024
/* ip首部 + tcp首部 + 数据缓冲区大小 */
#define IP_TCP_BUFF_SIZE IP_TCP_HEADER_LEN + BUFFER_SIZE

void err_exit(const char *err_msg)
{
    perror(err_msg);
    exit(1);
}

/* 原始套接字接收 */
void raw_socket_recv()
{
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    int sock_raw_fd, ret_len;
    char buf[IP_TCP_BUFF_SIZE];

    if ((sock_raw_fd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
        err_exit("socket()");

    /* 接收数据 */
    while (1)
    {
        bzero(buf, IP_TCP_BUFF_SIZE);
        ret_len = recv(sock_raw_fd, buf, IP_TCP_BUFF_SIZE, 0);
        if (ret_len > 0)
        {
            /* 取出ip首部 */
            ip_header = (struct ip *)buf;
            /* 取出tcp首部 */
            tcp_header = (struct tcphdr *)(buf + IP_HEADER_LEN);
            printf("=======================================\n");
            printf("from ip:%s\n", inet_ntoa(ip_header->ip_src));
            printf("from port:%d\n", ntohs(tcp_header->source));
            /* 取出数据 */
            printf("get data:%s\n", buf + IP_TCP_HEADER_LEN);
        }
    }
    
    close(sock_raw_fd);
}

int main(void)
{
    /* 原始套接字接收 */
    raw_socket_recv();

    return 0;
}