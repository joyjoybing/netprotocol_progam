#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
int main()
{
	int ret;
	int sockfd;
	char buf[256];
	struct sockaddr_in srvaddr;     //服务端地址
	struct sockaddr_in cltaddr;    //客户端地址
	socklen_t addrlen;
 
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		perror("socket");
		return -1;
	}
    //加入组播组
	struct ip_mreqn mrq;//加入多播组的数据结构
	memset(&mrq, 0, sizeof(mrq));
	mrq.imr_multiaddr.s_addr = inet_addr("224.10.10.1");
	mrq.imr_address.s_addr = htonl(INADDR_ANY);
	setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mrq, sizeof(mrq));
	//bind
	memset(&srvaddr, 0, sizeof(struct sockaddr_in));
	srvaddr.sin_family = AF_INET;
	srvaddr.sin_port = htons(9999);
	srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	ret = bind(sockfd, (const struct sockaddr *)&srvaddr, sizeof(struct sockaddr));
	if (ret == -1 ) {
		perror("bind");
		return -1;
	}
	printf("link finish!\n");
	
	while(1) {
		memset(buf, 0, sizeof(buf));  //清空数组
		addrlen = sizeof(struct sockaddr);
		ret = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&cltaddr, &addrlen);
		if (ret == -1) {
			perror("recvfrom");
			return -1;
		}
		printf("buf : %s\n", buf);
	}
	return 0;
}
