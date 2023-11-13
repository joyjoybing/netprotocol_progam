#include <sys/types.h>          /* See NOTES */
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#define PORT 5001
#define BACKLOG 5
int main(int argc, char* argv[])
{
    struct sockaddr_in local,client;
    int len;
    int s_s=-1,s_c=-1;
    local.sin_family=AF_INET;
    local.sin_port=htons(PORT);
    local.sin_addr.s_addr=htonl(INADDR_ANY);
    
    s_s=socket(AF_INET,SOCK_STREAM/*|SOCK_NONBLOCK*/,0);

    fcntl(s_s,F_SETFL,O_NONBLOCK);
    bind(s_s,(struct sockaddr*)&local,sizeof(local));
    listen(s_s,BACKLOG);
    char buffer[1024]="def\r";
    printf("have listen\r\n");
    for(;;)
    {
	//printf("intofor..\r\n");
        while(s_c<0){
            s_c=accept(s_s,(struct sockaddr*)&client,&len);
        }
	printf("s_c=%d\r\n",s_c);
	int i=0;
        while(recv(s_c,buffer,1024,0)<=0){
	    printf("nonblock i=%d\n",i);
	    i++;
            ;
        }
	
	printf("buffer=%s\r",buffer);
        if(strcmp(buffer,"HELLO")==0){
            send(s_c,"ok",3,0);
            close(s_c);
	    printf("have send ok\r");
            continue;
        }
        if(strcmp(buffer,"SHUTDOWN")==0){
            send(s_c,"BYE",3,0);
            close(s_c);
            break;
        }
    }
    close(s_s);
    return 0;
}
