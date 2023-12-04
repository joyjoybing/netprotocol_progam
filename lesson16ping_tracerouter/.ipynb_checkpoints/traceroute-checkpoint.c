#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

struct sockaddr_in dst_addr;
struct sockaddr_in recv_addr;
char icmp_pkt[1024] = {0};
char recv_pkt[1024] = {0};
int bytes = 56, nsend_pkt = 0, nrecv_pkt = 0;

int in_chksum(unsigned short *buf, int size) {
  int nleft = size;
  int sum = 0;
  unsigned short *w = buf;
  unsigned short ans = 0;

  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }
  if (nleft == 1) {
    *(unsigned char *)(&ans) = *(unsigned char *)w;
    sum += ans;
  }
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  ans = ~sum;
  return ans;
}

int pack(int send_pkt, pid_t pid) {
  struct icmp *pkt = (struct icmp *)icmp_pkt;

  pkt->icmp_type = ICMP_ECHO;
  pkt->icmp_cksum = 0;
  pkt->icmp_seq = htons(nsend_pkt);
  pkt->icmp_id = pid;
  pkt->icmp_cksum = in_chksum((unsigned short *)pkt, bytes + 8);

  return bytes + 8;
}

void send_traceroute(int sockfd, pid_t pid) {
  int send_bytes = 0;
  int ret = -1;

  nsend_pkt++;
  send_bytes = pack(nsend_pkt, pid);
  ret = sendto(sockfd, icmp_pkt, send_bytes, 0, (struct sockaddr *)&dst_addr,
               sizeof(dst_addr));
  if (ret == -1) {
    printf("send fail\n");
    sleep(1);
    return;
  }
}

int unpack(int sockfd, char *recv_pkt, struct sockaddr_in *src_addr, int size,
           pid_t pid) {
  struct iphdr *ip = NULL;
  int iphdrlen;
  struct icmp *icmp;
  struct timeval *tvsend;
  double rtt;
  struct sockaddr peer_addr;
  struct sockaddr_in *tmp_addr = NULL;
  size_t len = 0;

  memset(&peer_addr, 0, sizeof(struct sockaddr));

  ip = (struct iphdr *)recv_pkt;
  iphdrlen = ip->ihl << 2;
  icmp = (struct icmp *)(recv_pkt + iphdrlen);

  size -= iphdrlen;
  if (size < 8) {
    printf("ICMP size is less than 8\n");
    return -1;
  }

  len = sizeof(peer_addr);

  if ((icmp->icmp_type == ICMP_TIME_EXCEEDED)) {
    tmp_addr = (struct sockaddr_in *)src_addr;
    printf("%s", inet_ntoa(tmp_addr->sin_addr));
  } else if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid)) {
    tmp_addr = (struct sockaddr_in *)src_addr;
    printf("%s", inet_ntoa(tmp_addr->sin_addr));
    return 1;
  }
  return 0;
}

int recv_traceroutes(int sockfd, pid_t pid) {
  fd_set rd_set;
  struct timeval time;
  time.tv_sec = 5;
  time.tv_usec = 0;
  int ret = 0, nread = 0, recv_len = 0;

  recv_len = sizeof(recv_addr);
  FD_ZERO(&rd_set);
  FD_SET(sockfd, &rd_set);
  ret = select(sockfd + 1, &rd_set, NULL, NULL, &time);
  if (ret <= 0) {
    return -1;
  } else if (FD_ISSET(sockfd, &rd_set)) {
    nread = recvfrom(sockfd, recv_pkt, sizeof(recv_pkt), 0,
                     (struct sockaddr *)&recv_addr, (socklen_t *)&recv_len);
    if (nread < 0) {
      return -1;
    }

    ret = unpack(sockfd, recv_pkt, &recv_addr, nread, pid);
    return ret;
  }
}

int main(int argc, char **argv) {
  int size = 50 * 1024;
  int errno = -1;
  int tried_times = 30, i = 0;
  int ttl = 0, ret = 0;
  int sockfd = 0;
  struct in_addr ipv4_addr;
  struct hostent *ipv4_host;
  struct protoent *protocol = NULL;
  pid_t pid;

  protocol = getprotobyname("icmp");
  pid = getpid();

  for (i = 0; i < tried_times; i++) {
    ttl = i + 1;

    sockfd = socket(AF_INET, SOCK_RAW, protocol->p_proto);
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    errno = inet_aton(argv[1], &ipv4_addr);
    if (errno == 0) {
      ipv4_host = gethostbyname(argv[1]);
      if (NULL == ipv4_host) {
        printf("connect: Invalid argument\n");
        return -1;
      }
      memcpy(&(dst_addr.sin_addr), ipv4_host->h_addr, sizeof(struct in_addr));
    } else {
      memcpy(&(dst_addr.sin_addr), &(ipv4_addr.s_addr), sizeof(struct in_addr));
    }
    printf("\n%d	", i + 1);
    send_traceroute(sockfd, pid);
    ret = recv_traceroutes(sockfd, pid);
    close(sockfd);
    if (ret == 1) {
      break;
    }
  }
  return 0;
}