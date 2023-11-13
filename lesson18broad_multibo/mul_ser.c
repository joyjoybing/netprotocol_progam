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
	struct sockaddr_in srvaddr;//服务端地址
 
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		perror("socket");
		return -1;
	}
	memset(&srvaddr, 0, sizeof(struct sockaddr_in));
	srvaddr.sin_family = AF_INET;
	srvaddr.sin_port = htons(9999);
	srvaddr.sin_addr.s_addr = inet_addr("224.10.10.1");
 
	while(1) {
		fgets(buf, sizeof(buf), stdin);
		ret = sendto(sockfd, buf, sizeof(buf), 0, (const struct sockaddr *)&srvaddr, sizeof(struct sockaddr));
		if (ret == -1) {
			perror("sendto");
			return -1;
		}
		printf("ret = %d\n", ret);
	}
	return 0;
}
