
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <net/ethernet.h>

/* 以太网帧首部长度 */
#define ETHER_HEADER_LEN sizeof(struct ether_header)
/* 整个arp结构长度 */
#define ETHER_ARP_LEN sizeof(struct ether_arp)
/* 以太网 + 整个arp结构长度 */
#define ETHER_ARP_PACKET_LEN ETHER_HEADER_LEN + ETHER_ARP_LEN
/* IP地址长度 */
#define IP_ADDR_LEN 4

void Err_exit(const char *err_msg)
{
    perror(err_msg);
    exit(1);
}

int main(void)
{
    struct ether_arp *arp_packet;
    char buf[ETHER_ARP_PACKET_LEN];
    int sock_raw_fd, ret_len, i;

    if ((sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1)
        Err_exit("socket()");

    while (1)
    {
        bzero(buf, ETHER_ARP_PACKET_LEN);
        ret_len = recv(sock_raw_fd, buf, ETHER_ARP_PACKET_LEN, 0);
        if (ret_len > 0)
        {
            /* 剥去以太头部 */
            arp_packet = (struct ether_arp *)(buf + ETHER_HEADER_LEN);
            /* arp操作码为2代表arp应答 */
            if (ntohs(arp_packet->arp_op) == 1)
            {
                printf("==========================arp replay======================\n");
                printf("from ip:");
                for (i = 0; i < IP_ADDR_LEN; i++)
                    printf(".%u", arp_packet->arp_spa[i]);
                printf("\nfrom mac");
                for (i = 0; i < ETH_ALEN; i++)
                    printf(":%02x", arp_packet->arp_sha[i]);
                printf("\n");
            }
        }
    }

    close(sock_raw_fd);
    return 0;
}