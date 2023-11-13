#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>						/*包含socket()/bind()*/
#include <netinet/in.h>						/*包含struct sockaddr_in*/
#include <string.h>							/*包含memset()*/
#define PORT_SERV 8888						/*服务器端口*/
#define BUFF_LEN 256							/*缓冲区大小*/
#define PACKET_MAX_SEQ 1000
#define LENGTH 1024
char buff_send[LENGTH];
static void udpclie_echobak(int s, struct sockaddr*to)
{
	char buff[BUFF_LEN] = "MY sss UDP TEST";			/*发送给服务器的测试数据05	*/
	struct sockaddr_in from;					/*服务器地址*/
	socklen_t len = sizeof(*to);						/*地址长度*/
	sendto(s, buff, BUFF_LEN, 0, to, len);		/*发送给服务器*/
	int i=0;
	for(i=0;i<16;i++)
	{
		memset(buff,0,BUFF_LEN);
		int err=recvfrom(s,buff,1,0,(struct sockaddr*)&from,&len);
		printf("%dst:%s,err:%d\n",i,buff,err);
	}
	//recvfrom(s, buff, BUFF_LEN, 0, (struct sockaddr*)&from, &len);	
												/*从服务器接收数据*/
	printf("recved:%s\n",buff);					/*打印数据*/
	
} 

static void udpclie_echo(int s, struct sockaddr*to)
{
	char buff_init[BUFF_LEN] = "MY sss UDP TEST";			/*发送给服务器的测试数据05	*/
	struct sockaddr_in from;					/*服务器地址*/
	socklen_t len = sizeof(*to);						/*地址长度*/
	
	int i=0;
	for(i=0;i<160;i++)
	{
		*((int*)&buff_send[0])=htonl(i);
		memcpy(&buff_send[4],buff_init,sizeof(buff_init));
		//memset(buff,0,BUFF_LEN);
		//int err=recvfrom(s,buff,1,0,(struct sockaddr*)&from,&len);
	//	printf("%dst:%c,err:%d\n",i,buff[0],err);
		sendto(s, buff_send/* &buff_send[0] */, BUFF_LEN, 0, to, len);		/*发送给服务器*/
	}
	//recvfrom(s, buff, BUFF_LEN, 0, (struct sockaddr*)&from, &len);	
												/*从服务器接收数据*/
//	printf("recved:%s\n",buff);					/*打印数据*/
	
} 

struct udp_packet_costom
{
	int seq;
	char buffs[BUFF_LEN];
};
typedef struct udp_packet_costom  udpc;
static void udpclie_echome(int s, struct sockaddr*to)
{
	//udpc* pdata;
	//strcpy(pdata->buff,"CUSTOM UDP TEST");
	char buff[BUFF_LEN] = "UDP TEST";			/*发送给服务器的测试数据05	*/
	struct sockaddr_in from;					/*服务器地址*/
	socklen_t len = sizeof(*to);						/*地址长度*/
	int i=0;
	
	for(i=0;i<PACKET_MAX_SEQ;i++)
	{
		bzero(buff_send,LENGTH);
		*((int*)&buff_send[0])=htonl(i);
		memcpy(&buff_send[4],buff,sizeof(buff));
		printf("recved:%s\n",buff);	
		sendto(s,&buff_send[0],PACKET_MAX_SEQ,0,to,len);
	}
	//sendto(s, buff, BUFF_LEN, 0, to, len);		/*发送给服务器*/
	//recvfrom(s, buff, BUFF_LEN, 0, (struct sockaddr*)&from, &len);	
												/*从服务器接收数据*/
//	printf("recved:%s\n",buff);					/*打印数据*/
}


int main(int argc, char*argv[])
{
	int s;											/*套接字文件描述符*/
	struct sockaddr_in addr_serv;					/*地址结构*/
	
	s = socket(AF_INET, SOCK_DGRAM, 0);			/*建立数据报套接字*/
	
	memset(&addr_serv, 0, sizeof(addr_serv));		/*清空地址结构*/
	addr_serv.sin_family = AF_INET;				/*地址类型为AF_INET*/
	addr_serv.sin_addr.s_addr = htonl(INADDR_ANY);	/*任意本地地址*/
	addr_serv.sin_port = htons(PORT_SERV);			/*服务器端口*/
	
	udpclie_echome(s, (struct sockaddr*)&addr_serv);	/*客户端回显程序*/
	
	close(s);
	return 0;	
}
