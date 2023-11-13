//信号驱动式I/O不适用于TCP套接字, 因为产生的信号过于频繁且不能准确判断信号产生的原因.
	//设置信号驱动需把sockfd的非阻塞与信号驱动属性都打开
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#define MAXLINE 1024
#define SERV_PORT 5555
void err_quit(const char *s){
	perror(s);
	exit(1);
}
int sockfd; //sockfd单独提出来作为全局变量, 便于sig_io处理函数访问
struct data{
	struct sockaddr addr;
	char data[1024];
}DATA;   //struct data结构作为信号处理函数中保存客户端信息的记录地址
static int num=0;  //num变量用于设置当前可读数据报数量
void sig_io(int signo){
	ssize_t nread;
	char *buff=DATA.data;
	int size=sizeof(DATA.data);
	socklen_t slen=sizeof(DATA.addr);
	nread=recvfrom(sockfd,buff,size,0,&DATA.addr,&slen);
	printf("in function sig_io, print sigio_driver\n");
	if(nread < 0){
		if(errno == EWOULDBLOCK)
			return;
		else
			err_quit("recvfrom");
	}
	buff[nread]=0;
	num++;
}
int main(int argc,char *argv[]){
	struct sockaddr_in servaddr;
	sockfd=socket(AF_INET,SOCK_DGRAM,0);
	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family=AF_INET;
	servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
	servaddr.sin_port=htons(SERV_PORT);
	if(bind(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr)) < 0)
		err_quit("bind");
	int on = 1;
	signal(SIGIO,sig_io);
	fcntl(sockfd,F_SETOWN,getpid());
	ioctl(sockfd,FIOASYNC,&on);
	ioctl(sockfd,FIONBIO,&on);
	sigset_t zeromask,newmask,oldmask;
	sigemptyset(&zeromask);
	sigemptyset(&newmask);
	sigemptyset(&oldmask);
	sigaddset(&newmask,SIGIO);
	sigaddset(&newmask,SIGINT);
/*	sigprocmask函数提供屏蔽和解除屏蔽信号的功能。
		从而实现关键代码的运行不被打断。
		函数声明如下：  
#include <signal.h>
		int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
	其中参数 how可设置的参数为：SIG_BLOCK， SIG_UNBLOCK，SIG_SETMASK
		SIG_BLOCK：
		按照参数  set 提供的屏蔽字，屏蔽信号。并将原信号屏蔽保存到oldset中。

		SIG_UNBLOCK：
		按照参数  set 提供的屏蔽字进行信号的解除屏蔽。针对Set中的信号进行解屏。
SIG_SETMASK:
	按照参数  set 提供的信号设置重新设置系统信号设置。*/
	sigprocmask(SIG_BLOCK,&newmask,&oldmask);
	sleep(8);
	for(;;){
		while(num == 0)
			sigsuspend(&zeromask);//sigsuspend取消信号的屏蔽，直到signal driver 执行
		//sigprocmask(SIG_BLOCK,&newmask,&oldmask);  //一个进程的信号屏蔽字规定了当前阻塞而不能递送给该进程的信号集。
		//sigprocmask(SIG_SETMASK,&oldmask,NULL);
		sendto(sockfd,DATA.data,strlen(DATA.data),0,&DATA.addr,sizeof(DATA.addr));
		sigprocmask(SIG_BLOCK,&newmask,&oldmask);
		if(num > 0)
			num--;
	}
	return 0;
}
