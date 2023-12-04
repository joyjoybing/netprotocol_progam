#include<stdio.h>
#include<stdlib.h>
#include<string.h>    //strlen
#include<sys/socket.h>
#include<arpa/inet.h> //inet_addr
#include<netdb.h>
#include<errno.h>

#define SERV_PORT 8080


int main(int argc, char *argv[])
{
    int socket_desc;
    struct sockaddr_in server;
    char *message;
	FILE *fp = NULL;
	// open browser to save the html
	if( (fp=fopen("index.html","wt")) == NULL ){
        perror("Fail to open file!");
    }

    //Create socket
    socket_desc = socket(AF_INET, SOCK_STREAM , 0);
    if (socket_desc == -1) {
        printf("Could not create socket");
    }

    char ip[20] = {0};
    char *hostname = "127.0.0.1";
    struct hostent *hp;
    if ((hp = gethostbyname(hostname)) == NULL) {
        return 1;
    }
    
    strcpy(ip, inet_ntoa(*(struct in_addr *)hp->h_addr_list[0]));

    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_family = AF_INET;
    server.sin_port = htons(SERV_PORT);


    //Connect to remote server
    if (connect(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0)     {
        printf("connect error： %d", errno);
        return 1;
    }

    puts("Connected\n");

    //Send some data
    //http 协议
    message = "GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";

    //向服务器发送数据
    if (send(socket_desc, message, strlen(message) , 0) < 0) {
        puts("Send failed");
        return 1;
    }
    puts("Data Send\n");

    struct timeval timeout = {3, 0};
    setsockopt(socket_desc, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

    //Receive a reply from the server
    //loop
    int size_recv, total_size = 0;
    char chunk[128];
	int i = 0;
    while(1) {
        memset(chunk , 0 , 128); //clear the variable
        //获取数据
        if ((size_recv =  recv(socket_desc, chunk, 1, 0) ) == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                printf("recv timeout ...\n");
                break;
            } else if (errno == EINTR) {
                printf("interrupt by signal...\n");
                continue;
            } else if (errno == ENOENT) {
                printf("recv RST segement...\n");
                break;
            } else {
                printf("unknown error: %d\n", errno);
                exit(1);
            }
        } else if (size_recv == 0) {
            printf("\npeer closed ...\n");
            break;
        } else {
            total_size += size_recv;
			// 下载html文件
			// find the http body
			if(i < 4){
				if(chunk[0] == '\r' || chunk[0] == '\n'){
					i++;
				}else{
					i ^= i;
				}
			}else{ //finding it.
				printf("%c" , chunk[0]);
				fputc(chunk[0], fp);
			}
        }
    }

	fputc('\n', fp);
	fclose(fp);

    printf("Reply received, total_size = %d bytes\n", total_size);
    return 0;
}
