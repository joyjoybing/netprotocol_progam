#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#define BUF_LENGTH 1024

int main()
{
	int sockfd;
	//创建原始套接字
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		pthread_exit(NULL);
	}
	int ret;
	while (1)
	{
		unsigned char buf[1600] = {};
		char src_mac[6] = {};
		char dest_mac[6] = {};
		ret = recvfrom(sockfd, buf, sizeof(buf), 0, NULL, NULL);
		//从接收到的数据中获取源mac地址、目的mac地址以及类型
		sprintf(dest_mac, "%x:%x:%x:%x:%x:%x",buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
		sprintf(src_mac, "%x:%x:%x:%x:%x:%x",buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]);
		
		printf("------------------mac----------------------\n");
		printf("source mac:%s \n", src_mac);
		printf("destination mac:%s\n", dest_mac);
		//上一层使用的类型
		unsigned short mac_type = ntohs(*(unsigned short*)(buf + 12));
		if (mac_type == 0x800)
		{
			printf("****ip protocal****\n");
			//取出ip头部
			struct ip* ip_header = (struct ip*)(buf+14);
			printf("The total length of ip packet :%d\n", ip_header->ip_len);/* 取出tcp首部 */
			// ip头部长度
			unsigned int ip_header_lenth = (ip_header->ip_hl) << 2;
			unsigned char ip_type = ip_header->ip_p;
			if (ip_type == 1)
			{
				printf("**icmp protocal**\n");
				
			}
			else if(ip_type==6)
			{
				printf("**tcp protocal**\n");
				
				struct tcphdr* tcp_header = (struct tcphdr*)(buf + ip_header_lenth);
				unsigned short sport = tcp_header->source;
				unsigned short dport = tcp_header->dest;
				printf("source port:%d\n", sport);
				printf("desination port:%d\n", dport);
			}
			else if(ip_type==17)
			{
				printf("**udp protocal**\n");
				struct udphdr* udp_header = (struct udphdr*)(buf + ip_header_lenth);
				unsigned short sport = udp_header->source;
				unsigned short dport = udp_header->dest;
				printf("source port:%d\n", sport);
				printf("desination port:%d\n", dport);
			}
			printf("source ip ip:%s\n", inet_ntoa(ip_header->ip_src));
			printf("destination ip ip:%s\n", inet_ntoa(ip_header->ip_dst));
			printf("-------------------------------------------\n\n");


		}
		else if(mac_type==0x0806)
		{
			printf("****arp protocal****\n");
		}

	
	}
	return 0;
}

