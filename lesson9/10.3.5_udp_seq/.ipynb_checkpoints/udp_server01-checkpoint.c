#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>						/*包含socket()/bind()*/
#include <netinet/in.h>						/*包含struct sockaddr_in*/
#include <string.h>							/*包含memset()*/
#define PORT_SERV 5000/*服务器端口*/
#define BUFF_LEN 256									/*缓冲区大小*/
#define PACKET_SEQ 160
#define LENGTH 1024
static void udpserv_echo(int s, struct sockaddr*client)
{
	int n;												/*接收数据长度*/
	char buff[BUFF_LEN];								/*接收发送缓冲区															*/
	socklen_t len;											/*地址长度*/
	while(1)											/*循环等待*/
	{
		len = sizeof(*client);
		n = recvfrom(s, buff, BUFF_LEN, 0, client, &len);
        printf("recv bytes is %d,buff=%s/n",n,buff);
								/*接收数据放到buff中，并获得客户端地址*/
		sendto(s, buff, n, 0, client, len);/*将接收到的n个字节发送回客户												端*/
	}	
}
static char buff[PACKET_SEQ][LENGTH];
static void udpserv_echoseq(int s, struct sockaddr*client)
{
	int n;												/*接收数据长度*/
	char tmp_buff[LENGTH];								/*接收发送缓冲区															*/
	socklen_t len;		/*地址长度*/
	
	while(1)											/*循环等待*/
	{
		bzero(tmp_buff,LENGTH);
		len = sizeof(*client);
		n = recvfrom(s, tmp_buff, LENGTH, 0, client, &len);
        printf("recv bytes is %d,tmp_buff=%s\n",n,tmp_buff);
								/*接收数据放到buff中，并获得客户端地址*/
		//sendto(s, buff, n, 0, client, len);/*将接收到的n个字节发送回客户端*/
		//uint32_t* pi=(uint32_t *)tmp_buff;
		//uint32_t seq=htonl(*pi);
		//printf("seq=%d\n",seq);
		//memcpy(&buff[seq][0],tmp_buff+4,n-4);
		//ntohl(*((int*)&tmp_buff[0]));
		/*uint32_t seq=ntohl(*((uint32_t*)&tmp_buff));
		printf("index=%u\t",seq);
		
		memcpy(&buff[seq][0],tmp_buff+4,n-4);
		printf(" data is: %s\n",&buff[seq][0]);*/
        uint32_t seq=ntohl(*((uint32_t*)&tmp_buff));
        printf("seq=%d,recved:%s\n",seq,tmp_buff+4);
        sendto(s,tmp_buff,n,0,client,len);
	}	
}

int main(int argc, char*argv[])
{
	int s;									/*套接字文件描述符*/
	struct sockaddr_in addr_serv,addr_clie;		/*地址结构*/
	
	s = socket(AF_INET, SOCK_DGRAM, 0);			/*建立数据报套接字*/
	
	memset(&addr_serv, 0, sizeof(addr_serv));		/*清空地址结构*/
	addr_serv.sin_family = AF_INET;				/*地址类型为AF_INET*/
	addr_serv.sin_addr.s_addr = htonl(INADDR_ANY);	/*任意本地地址*/
	addr_serv.sin_port = htons(PORT_SERV);			/*服务器端口*/
	
	bind(s, (struct sockaddr*)&addr_serv, sizeof(addr_serv));
													/*绑定地址*/
	udpserv_echoseq(s, (struct sockaddr*)&addr_clie);	/*回显处理程序*/
	
	return 0;	
}
