#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

#define BUF_SIZE 4096
#define ICMP_SIZE (sizeof(struct icmp))
int PROTO_ICMP = -1;

char *dest_ip_addr; // 接收目的IP地址
char sendbuf[ICMP_SIZE]; // 发送缓冲区
char recvbuf[BUF_SIZE];	 //接收缓冲区

int icmp_time(); // 时间轴请求主程序
int get_time(); // 获取时间
void handler(int sig); // 信号处理函数
unsigned short icmp_chksum(unsigned short *addr,int len); //校验函数

int main(int argc, char* argv[]) 
{
	if (argc < 2) {
		printf("Usage: %s <Destination IP Address>\n", argv[0]);
		exit(0);
	}
	dest_ip_addr = argv[1];
	signal(SIGALRM, handler);
	icmp_time();
}

int icmp_time()
{
	struct ip *iph;
	struct icmp *icmp_echo,*icmp_reply;
	struct sockaddr_in dst_addr; // 填充目标主机地址
	struct protoent* protocol = NULL;
	int sockfd,ret,nr;

	protocol = getprotobyname("icmp");
	PROTO_ICMP = protocol->p_proto;     //ICMP协议的值

	// 创建原始套接字, 只接收承载 ICMP 协议的数据报
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(sockfd < 0)
	{
		printf("Fail to create socket!\n");
		exit(0);
	}
	
	icmp_echo = (struct icmp*)sendbuf;
	iph = (struct ip*)recvbuf;

	//填写ICMP目的地址
	dst_addr.sin_family =  AF_INET; 
	dst_addr.sin_addr.s_addr = inet_addr(dest_ip_addr);
 
	//时间戳请求的type字段为13，code字段为0
	icmp_echo->icmp_type = 13;	
	icmp_echo->icmp_code = 0;
	icmp_echo->icmp_id = getpid() & 0xffff;
	icmp_echo->icmp_cksum = 0;
	icmp_echo->icmp_seq = 0;
	icmp_echo->icmp_otime = get_time(); //发起时间，对端不处理，返回原值
	icmp_echo->icmp_rtime = 0;	//接收时间戳，本端填0
	icmp_echo->icmp_ttime = 0;	//发送时间戳，本端填0
	icmp_echo->icmp_cksum = icmp_chksum((unsigned short*)icmp_echo,ICMP_SIZE); 

	ret = sendto(sockfd, sendbuf, ICMP_SIZE, 0, (struct sockaddr*)&dst_addr, sizeof(dst_addr));
	if(ret<0)
	{
		printf("sendto error\n");
		exit(0);
	}

	while(1)
	{
		alarm(1); //等待1秒后产生SIGALRM信号
		nr = recvfrom(sockfd, recvbuf, BUF_SIZE, 0, NULL, NULL);
		if (nr < 0) 
		{
			printf("recvfrom error");
			exit(0);
		}
		icmp_reply = (struct icmp*)((char*)iph + (iph->ip_hl << 2));  //获取ICMP数据
		
		if (icmp_reply->icmp_type == 14 && icmp_reply->icmp_id == (getpid() & 0xffff))	//时间戳的响应type字段为14
		{
			// 收到正确响应的包，退出循环
			break;
		}
	}

	//接收和发送时间戳返回的时间为UTC时间，单位为毫秒
	printf("type = %d, seq = %d, orig = %u, recv = %u, send = %u, from = %s\n",
			icmp_reply->icmp_type,
			icmp_reply->icmp_seq,
			icmp_reply->icmp_otime,
			ntohl(icmp_reply->icmp_rtime),
			ntohl(icmp_reply->icmp_ttime),
			inet_ntoa(iph->ip_src));
}

int get_time() //获取当前时间
{
	time_t timep;
	struct tm *tm;
	struct timeval ti;
	long int time_ms;
	//获取当前系统时间，精确到秒
	time(&timep);
	tm = localtime(&timep);
	time_ms = (tm->tm_hour*60*60)+(tm->tm_min*60)+tm->tm_sec;
	time_ms = time_ms * 1000;
	//获取时间精确到毫秒
	gettimeofday( &ti, NULL );
	time_ms += ti.tv_usec/1000;
   
	return time_ms;
}

void handler(int sig)	//信号处理函数
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
