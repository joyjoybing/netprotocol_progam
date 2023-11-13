#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <arpa/inet.h>

#define BUF_SIZE 4096
#define ICMP_SIZE (sizeof(struct icmp))

char sendbuf[ICMP_SIZE]; // 发送缓冲区
char recvbuf[BUF_SIZE]; //接收缓冲区
const char *strings[1] = { "I'm icmp echo\n"}; //发送数据

char *dst_ip; //目的IP地址
int PROTO_ICMP = -1;

int icmp_echo(); // ICMP回显应答主程序
void handler(int sig); // 信号处理函数
unsigned short icmp_chksum(unsigned short *addr,int len); //用于计算ICMP数据校验和

int main(int argc, char* argv[]) {
	if (argc < 2) {
		printf("Usage: %s <Destination IP Address>\n", argv[0]);
		exit(0);
	}
	dst_ip = argv[1];
	signal(SIGALRM, handler);
	icmp_echo();
}

int icmp_echo()
{
	struct ip *iph;
	struct icmp *icmp_echo,*icmp_reply;
	struct sockaddr_in dst_addr; // 目标主机地址
	struct protoent* protocol = NULL;
	int sockfd,ret,nr,len;

	protocol = getprotobyname("icmp");
	PROTO_ICMP = protocol->p_proto; //获取ICMP协议的值

	//填写发送目的地址部分
	dst_addr.sin_family =  AF_INET; 
	dst_addr.sin_addr.s_addr = inet_addr(dst_ip);


	icmp_echo = (struct icmp*)sendbuf;
	iph = (struct ip*)recvbuf;
	
	//计算ICMP数据的长度
	len = strlen(strings[0]);
	len = ICMP_SIZE + len;

	//填充ICMP数据
	icmp_echo->icmp_type = 8;
	icmp_echo->icmp_code = 0;
	icmp_echo->icmp_cksum = 0;
	icmp_echo->icmp_seq = 0;
	icmp_echo->icmp_id = getpid() & 0xffff;
	strcpy(icmp_echo->icmp_data,strings[0]);

	icmp_echo->icmp_cksum = icmp_chksum((unsigned short*)icmp_echo,len);

	// 创建原始套接字, 只接收承载 ICMP 协议的数据报
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(sockfd < 0)
	{
		printf("Fail to create socket!\n");
		exit(0);
	}
	//发送数据
	ret = sendto(sockfd, sendbuf, len, 0, (struct sockaddr*)&dst_addr, sizeof(dst_addr));
	if(ret<0)
	{
		printf("sendto error\n");
		exit(0);
	}
	while(1)
	{
		alarm(1); //等待1秒后产生SIGALRM信号
		//接收数据
		nr = recvfrom(sockfd, recvbuf, BUF_SIZE, 0, NULL, NULL);
		if(ret<0)
		{
			printf("recvfrom error\n");
			exit(0);
		}

		icmp_reply = (struct icmp*)((char*)iph + (iph->ip_hl << 2));
		if ((icmp_reply->icmp_type == 0 && icmp_reply->icmp_id == (getpid() & 0xffff)))
		{
			// 收到正确响应的包，退出循环
			break;
		}
	}
	printf("---------------ICMP ECHO---------------\n");
	printf("src_ip:			%s\n", inet_ntoa(iph->ip_src));
	printf("det_ip：		%s\n", inet_ntoa(iph->ip_dst));
	printf("icmp_type:		%d\n",icmp_reply->icmp_type);
	printf("icmp_code:		%d\n",icmp_reply->icmp_code);
	printf("icmp_id:		%d\n",icmp_reply->icmp_id);
	printf("icmp_seq:		%d\n",icmp_reply->icmp_seq);
	printf("icmp_data:		%s\n",icmp_reply->icmp_data);
	printf("----------------------------------------\n");
	
}

void handler(int sig)  //信号处理函数
{
	printf("no reply\n");
	exit(0);
}

unsigned short icmp_chksum(unsigned short *addr,int len) //用于计算ICMP数据校验和
{       
	int icmp_len=len;
	int sum=0;
	unsigned short *icmp=addr;

	/*把ICMP报头二进制数据以2字节为单位累加起来*/
	while(icmp_len>1)
	{
		sum+= *icmp++;
		icmp_len-=2;
	}
	/*若ICMP报头为奇数个字节，会剩下最后一字节，需要处理最后一个字节*/
	if( icmp_len==1)
	{
		sum+=*(unsigned char *)icmp;
	}
	// 将32位的高16位与低16位相加
	sum=(sum>>16)+(sum&0xffff);
	sum+=(sum>>16);
	return (unsigned short) ~sum;
}