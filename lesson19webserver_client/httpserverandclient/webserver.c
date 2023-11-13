#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#define PORT 8080                       // 服务器监听端口

int send_respond(int client_socket, char res[]);

int main(){
    
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT);

	// set port rebind
	int opt = 1;
	setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt, sizeof(opt));
    
    bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
    
    listen(server_socket, 5);
    
    int client_socket = accept(server_socket, NULL, NULL);
    
    char buf[4096];
    read(client_socket, buf, 4096);
    
    printf("%s",buf);

	if(buf[0] == 'G'){
		char *temp = "GET";
		send_respond(client_socket, temp);
	}
	else if(buf[0] == 'P'){
		char *temp = "POST";
		send_respond(client_socket, temp);
	}
	else{
		char *temp = "OTHER";
		send_respond(client_socket, temp);
	}

    close(client_socket);
    close(server_socket);

    return 0;
}

int send_respond(int client_socket, char res[]){
	if(client_socket < 0) return -1;
	char status[] = "HTTP/1.0 200 OK\r\n";
	char header[] = "Server: DWBServer\r\nContent-Type: text/html;charset=utf-8\r\n\r\n";
	char temp[] = "<html><head><title>%s</title></head><body><h2>欢迎</h2><p>Hello，World</p></body></html>";
	char body[4096] = "";
	sprintf(body, temp, res);
	write(client_socket, status, sizeof(status));
	write(client_socket, header, sizeof(header));
	write(client_socket, body, sizeof(body));

	return 0;
}
