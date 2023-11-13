#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <inttypes.h>
#include <getopt.h>
#include <pthread.h>
#include <string.h>
#include <time.h>

// 全局变量
uint8_t cont = 1;
time_t startTime;
volatile uint64_t pcktCount = 0;    //包的数量
volatile uint64_t totalData = 0;    //发送的字节数据总量


void parse_command_line(int argc, char* argv[]);    //输入拆解




#define MAX_PCKT_LENGTH 0xFFFF  //包的最大值
//线程结构
struct pthread_info {
    char* interface;    //接口
    char* sIP;          //源IP
    char* dIP;          //目的IP
    uint16_t port;      //目的端口
    uint16_t sport;     //源端口
    uint64_t interval;  //以微秒为单位发送数据包的间隔
    uint16_t min;       //最小有效负载长度
    uint16_t max;       //最大有效负载长度
    uint64_t pcktCountMax;  //允许发送的最大数据包数。
    time_t seconds;         //秒
    uint8_t payload[MAX_PCKT_LENGTH];   //有效载荷的最大值数组
    char* payloadStr;       //有效负载值
    uint16_t payloadLength; //有效负载长度                    
    int icmp;
    int verbose;    //打印每次发送的数据量。
    int internal;   //设置时，如果未指定源IP，它将从10.0中随机分配源IP。0.0 / 8范围。
    int nostats;    //不跟踪PPS和带宽。这可能会提高性能。
    int icmp_type;
    int icmp_code;
    int help;
    uint8_t sMAC[ETH_ALEN];
    uint8_t dMAC[ETH_ALEN];
    uint16_t threads;   //线程数量
    int nocsum;         //不计算IP报头的校验和。适用于硬件上的校验和卸载，从而提高性能。
    int nocsum4;        //不计算第4层的校验和（例如TCP/UDP）。它将在标题中将校验和字段保留为0。
    uint8_t minTTL; //最大TTL值
    uint8_t maxTTL; //最小TTL值
    uint8_t tos;    //服务类型

    time_t startingTime;
    uint16_t id;    //本结构ID
}g_info;


void signalHndl(int tmp)
{
    cont = 0;
}

uint16_t randNum(uint16_t min, uint16_t max, unsigned int seed)
{
    return (rand_r(&seed) % (max - min + 1)) + min;
}

// 命令行选项
static struct option longoptions[] =
{
    {"dev", required_argument, NULL, 'i'},//当第三参数NULL时，返回第四参数的值
    {"src", required_argument, NULL, 's'},
    {"dst", required_argument, NULL, 'd'},
    {"port", required_argument, NULL, 'p'},
    {"sport", required_argument, NULL, 14},//如果第三参数不为空，\
                                            那么当选中某个长选项的时候，getopt_long将返回0，并且将flag指针参数指向val值。
    {"interval", required_argument, NULL, 1},
    {"threads", required_argument, NULL, 't'},
    {"min", required_argument, NULL, 2},
    {"max", required_argument, NULL, 3},
    {"count", required_argument, NULL, 'c'},
     {"time", required_argument, NULL, 6},
    {"payload", required_argument, NULL, 10},
    {"verbose", no_argument, &g_info.verbose, 'v'},
    {"icmp", no_argument, &g_info.icmp, 4},
    {"internal", no_argument, &g_info.internal, 5},
    {"nostats", no_argument, &g_info.nostats, 9},
    {"icmptype", required_argument, NULL, 12},
    {"icmpcode", required_argument, NULL, 13},
    {"nocsum", no_argument, &g_info.nocsum, 17},
    {"nocsum4", no_argument, &g_info.nocsum4, 18},
    {"minttl", required_argument, NULL, 19},
    {"maxttl", required_argument, NULL, 20},
    {"tos", required_argument, NULL, 21},
    {"help", no_argument, &g_info.help, 'h'},
    {NULL, 0, NULL, 0}
};



void parse_command_line(int argc, char* argv[])
{
    int c = -1;

    // 解析命令行。
    while (optind < argc)   //optind:下一个将被处理到的参数在argv中的下标值
    {
        if ((c = getopt_long(argc, argv, "i:d:t:vhs:p:c:", longoptions, NULL)) != -1)
        {
            switch (c)
            {
            case 'i':
                g_info.interface = optarg;  //optarg:表示当前选项对应的参数值。

                break;

            case 's':
                g_info.sIP = optarg;

                break;

            case 'd':
                g_info.dIP = optarg;

                break;

            case 'p':
                g_info.port = atoi(optarg);

                break;

            case 14:
                g_info.sport = atoi(optarg);

                break;

            case 1:
                g_info.interval = strtoll(optarg, NULL, 10);//字符串转换成long long int类型的10进制数

                break;

            case 't':
                g_info.threads = atoi(optarg);

                break;

            case 2:
                g_info.min = atoi(optarg);

                break;

            case 3:
                g_info.max = atoi(optarg);

                break;

            case 'c':
                g_info.pcktCountMax = strtoll(optarg, NULL, 10);

                break;

            case 6:
                g_info.seconds = strtoll(optarg, NULL, 10);

                break;

            case 10:
                g_info.payloadStr = optarg;

                break;

            case 12:
                g_info.icmp_type = atoi(optarg);

                break;

            case 13:
                g_info.icmp_code = atoi(optarg);

                break;

            case 17:
                g_info.nocsum = 1;

                break;

            case 18:
                g_info.nocsum4 = 1;

                break;

            case 19:
                g_info.minTTL = (uint8_t)atoi(optarg);

                break;

            case 20:
                g_info.maxTTL = (uint8_t)atoi(optarg);

                break;

            case 21:
                g_info.tos = (uint8_t)atoi(optarg);

                break;

            case 'v':
                g_info.verbose = 1;

                break;

            case 'h':
                g_info.help = 1;

                break;

            case '?':
                fprintf(stderr, "Missing argument.\n");

                break;
            }
        }
        else
        {
            optind++;
        }
    }
}






/**
 * ip_fast_csum - Compute the IPv4 header checksum efficiently.
 * iph: ipv4 header
 * ihl: length of header / 4
 */

static inline __sum16 ip_fast_csum(const void* iph, unsigned int ihl)
{
    unsigned int sum;

    asm("  movl (%1), %0\n"
        "  subl $4, %2\n"
        "  jbe 2f\n"
        "  addl 4(%1), %0\n"
        "  adcl 8(%1), %0\n"
        "  adcl 12(%1), %0\n"
        "1: adcl 16(%1), %0\n"
        "  lea 4(%1), %1\n"
        "  decl %2\n"
        "  jne	1b\n"
        "  adcl $0, %0\n"
        "  movl %0, %2\n"
        "  shrl $16, %0\n"
        "  addw %w2, %w0\n"
        "  adcl $0, %0\n"
        "  notl %0\n"
        "2:"
        /* Since the input registers which are loaded with iph and ihl
           are modified, we must also specify them as outputs, or gcc
           will assume they contain their original values. */
        : "=r" (sum), "=r" (iph), "=r" (ihl)
        : "1" (iph), "2" (ihl)
        : "memory");
    return (__sum16)sum;
}


static __always_inline void update_iph_checksum(struct iphdr* iph) {
#ifndef __BPF__
    iph->check = 0;
    iph->check = ip_fast_csum((unsigned char*)iph, iph->ihl);
#else
    uint16_t* next_iph_u16 = (uint16_t*)iph;
    uint32_t csum = 0;
    iph->check = 0;
#pragma clang loop unroll(full)
    for (uint32_t i = 0; i < sizeof(*iph) >> 1; i++) {
        csum += *next_iph_u16++;
    }

    iph->check = ~((csum & 0xffff) + (csum >> 16));
#endif
}


uint16_t icmp_csum(uint16_t* addr, int len)
{
    int count = len;
    register uint32_t sum = 0;
    uint16_t answer = 0;

    // Sum up 2-byte values until none or only one byte left.
    while (count > 1)
    {
        sum += *(addr++);
        count -= 2;
    }

    // Add left-over byte, if any.
    if (count > 0)
    {
        sum += *(uint8_t*)addr;
    }

    // Fold 32-bit sum into 16 bits; we lose information by doing this,
    // increasing the chances of a collision.
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Checksum is one's compliment of sum.
    answer = ~sum;

    return (answer);
}


void* threadHndl(void* data)
{

    // 构建线程结构info.
    struct pthread_info* info = (struct pthread_info*)data;

    // 构建 sockaddr_ll struct.
    struct sockaddr_ll sin;

    // Fill out sockaddr_ll struct.
    sin.sll_family = PF_PACKET;//PF_PACKET。设置成这个选项后，\
                               从网卡接收的数据包可以直接传送到应用程序而不经过内核处理。
    //把接口转成对应的索引号
    sin.sll_ifindex = if_nametoindex(info->interface);   /* 接口类型 */
    sin.sll_protocol = htons(ETH_P_IP);     //一般是IP的话选ETH_P_IP
    sin.sll_halen = ETH_ALEN;    /* 地址长度 */ 

   
    //构建原始套接字
    int sockfd;
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
        perror("socket");

        pthread_exit(NULL);
    }


        // 接收接口的MAC地址（源MAC）。
        struct ifreq ifr;
        strcpy(ifr.ifr_name, info->interface);

        // 尝试获取MAC地址。
        if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) != 0)
        {
            perror("ioctl");

            pthread_exit(NULL);
        }

        // 把ifr中的MAC放入sMAC中
        memcpy(info->sMAC, ifr.ifr_addr.sa_data, ETH_ALEN);

    //把sMAC放入套接字的MAC中
    memcpy(sin.sll_addr, info->sMAC, ETH_ALEN);

    // 尝试绑定套接字。
    if (bind(sockfd, (struct sockaddr*)&sin, sizeof(sin)) != 0)
    {
        perror("bind");

        pthread_exit(NULL);
    }

    while (1)
    {
        uint16_t offset = 0;    //偏移量置0
        // 构建随机种子
        unsigned int seed;
        if (info->nostats)
        {
            seed = time(NULL) ^ getpid() ^ pthread_self();
        }
        else
        {
            seed = (unsigned int)(pcktCount + info->id);
        }

        // 获取源端口（随机）。
        uint16_t srcPort;

        // 检查源端口是否为0（随机）。
        if (info->sport == 0)
        {
            srcPort = randNum(1024, 65535, seed);
        }
        else
        {
            srcPort = info->sport;
        }

        // 获取目标端口。
        uint16_t dstPort;

        // 检查目的端口是否为0（随机）。
        if (info->port == 0)
        {
            dstPort = randNum(10, 65535, seed);
        }
        else
        {
            dstPort = info->port;
        }


        //构建ip
        char IP[32];

        //是否指定源IP
        if (info->sIP == NULL)
        {
            // 将源IP欺骗为任何IP地址。
            uint8_t tmp[4];

            if (info->internal)
            {
                tmp[0] = randNum(10, 10, seed);
                tmp[1] = randNum(0, 254, seed + 1);
                tmp[2] = randNum(0, 254, seed + 2);
                tmp[3] = randNum(0, 254, seed + 3);
            }
            else
            {
                tmp[0] = randNum(1, 254, seed);
                tmp[1] = randNum(0, 254, seed + 1);
                tmp[2] = randNum(0, 254, seed + 2);
                tmp[3] = randNum(0, 254, seed + 3);
            }

            sprintf(IP, "%d.%d.%d.%d", tmp[0], tmp[1], tmp[2], tmp[3]);
        }
        else
        {
            memcpy(IP, info->sIP, strlen(info->sIP));
        }

        // 初始化数据包缓冲区

        char buffer[MAX_PCKT_LENGTH];

        // 创建以太网报头。
        struct ethhdr* eth = (struct ethhdr*)(buffer);

        // 填写以太网报头。
        eth->h_proto = htons(ETH_P_IP);
        memcpy(eth->h_source, info->sMAC, ETH_ALEN);
        memcpy(eth->h_dest, info->dMAC, ETH_ALEN);


        // 增加以太网部分的偏移量。
        offset += sizeof(struct ethhdr);

        // 创建IP头。
        struct iphdr* iph = (struct iphdr*)(buffer + offset);

        //填充IP包头
        iph->ihl = 5;   //IP包头大小
        iph->version = 4;   //地址版本
        iph->protocol = IPPROTO_ICMP;
        iph->id = 0;
        iph->frag_off = 0;  //分段偏移
        iph->saddr = inet_addr(IP);
        iph->daddr = inet_addr(info->dIP);
        iph->tos = info->tos;

        iph->ttl = (uint8_t)randNum(info->minTTL, info->maxTTL, seed);

        // 增加IP包头的偏移量
        offset += sizeof(struct iphdr);


        // 计算有效载荷长度和有效载荷。
        uint16_t dataLen;  //有效载荷长度 

        uint16_t l4header;  //ICMP包头的偏移量

        l4header = sizeof(struct icmphdr);



        //  增加ICMP包头的偏移量
        offset += l4header;

        unsigned char* data = (unsigned char*)(buffer + offset);

        //检查自定义有效负载。
        if (info->payloadLength > 0)
        {
            dataLen = info->payloadLength;

           
            for (uint16_t i = 0; i < info->payloadLength; i++)
            {
                *data = info->payload[i];
                *data++;
            }
        }
        else
        {
            // 用随机字符填写有效负载。
            dataLen = randNum(info->min, info->max, seed);

            //计算有效负载大小
            for (uint16_t i = 0; i < dataLen; i++)
            {
                *data = rand_r(&seed);
                *data++;
            }
        }
        // 减小偏移量，因为我们将返回到L4层进行填充。
        offset -= l4header;

        // Create ICMP header.
        struct icmphdr* icmph = (struct icmphdr*)(buffer + offset);

        // Fill out ICMP header.
        icmph->type = info->icmp_type;
        icmph->code = info->icmp_code;

        // Calculate ICMP header's checksum.
        icmph->checksum = 0;

        if (!info->nocsum4)
        {
            icmph->checksum = icmp_csum((uint16_t*)icmph, sizeof(struct icmphdr) + dataLen);
        }
     
      

        uint16_t pcktlen = 0; //包长度

        //计算IP头的长度和校验和。
        pcktlen = sizeof(struct iphdr) + l4header + dataLen;

        iph->tot_len = htons(pcktlen);  //IP包长

        if (!info->nocsum)
        {
            update_iph_checksum(iph);
        }

        // 初始化表示已发送数据量的变量。
        uint16_t sent;

        //尝试发送数据。
        if ((sent = sendto(sockfd, buffer, pcktlen + sizeof(struct ethhdr), 0, (struct sockaddr*)&sin, sizeof(sin))) < 0)
        {
            perror("send");

            continue;
        }
       
        // 如果启用，则添加到统计信息。
        if (!info->nostats)
        {
            __sync_add_and_fetch(&totalData, sent);
        }

        if (!info->nostats || info->pcktCountMax > 0)
        {
            // 检查包数。
            if (__sync_add_and_fetch(&pcktCount, 1) >= info->pcktCountMax && info->pcktCountMax > 0)
            {
                cont = 0;

                break;
            }
        }

        // 是否打印发送的数据量。
        if (info->verbose)
        {
            fprintf(stdout, "Sent %d bytes to destination. (%" PRIu64 "/%" PRIu64 ")\n", sent, pcktCount, info->pcktCountMax);
        }

        // 检查时间返回值。
        //Check time elasped.
        if (info->seconds > 0)
        {
            time_t timeNow = time(NULL);

            if (timeNow >= (info->startingTime + info->seconds))
            {
                cont = 0;

                break;
            }
        }

        // 检查我们是否应该在数据包之间等待。
        if (info->interval > 0)
        {
            usleep(info->interval);
        }
    }

    // 关闭 socket.
    close(sockfd);

    // Free information.
    free(info);

    // Exit thread.
    pthread_exit(NULL);
}



int main(int argc, char* argv[])
{
    // 设置默认值
    g_info.threads = get_nprocs(); //返回可用CPU数量

    g_info.minTTL = 64;
    g_info.maxTTL = 64;
    g_info.interval = 1000000;  //以微秒为单位发送数据包的间隔
    g_info.tos = 0;

    g_info.startingTime = time(NULL);   //开始时间

    // Parse the command line.
    parse_command_line(argc, argv);

    // 检查是否设置了帮助标志。如果是，请打印帮助信息。
    if (g_info.help)
    {
        fprintf(stdout, "Usage for: %s:\n" \
            "--dev -i => Interface name to bind to.\n" \
            "--src -s => Source address (0/unset = random/spoof).\n"
            "--dst -d => Destination IP to send packets to.\n" \
            "--port -p => Destination port (0/unset = random port).\n" \
            "--sport => Source port (0/unset = random port).\n" \
            "--internal => When set, if no source IP is specified, it will randomize the source IP from the 10.0.0.0/8 range.\n" \
            "--interval => Interval between sending packets in micro seconds.\n" \
            "--threads -t => Amount of threads to spawn (default is host's CPU count).\n" \
            "--count -c => The maximum packet count allowed sent.\n" \
            "--time => Amount of time in seconds to run tool for.\n" \
            "--payload => The payload to send. Format is in hexadecimal. Example: FF FF FF FF 49.\n" \
            "--verbose -v => Print how much data we've sent each time.\n" \
            "--nostats => Do not track PPS and bandwidth. This may increase performance.\n" \
            "--min => Minimum payload length.\n" \
            "--max => Maximum payload length.\n" \
            "--icmp => Send ICMP packets.\n" \
            "--icmptype => The ICMP type to send when --icmp is specified.\n" \
            "--icmpcode => The ICMP code to send when --icmp is specified.\n" \
            "--nocsum => Do not calculate the IP header's checksum. Useful for checksum offloading on the hardware which'll result in better performance.\n" \
            "--nocsum4 => Do not calculate the layer 4's checksum (e.g. TCP/UDP). It will leave the checksum field as 0 in the headers.\n" \
            "--minttl => The minimum TTL (Time-To-Live) range for a packet.\n" \
            "--maxttl => The maximum TTL (Time-To-Live) range for a packet.\n" \
            "--tos => The TOS (Type Of Service) to set on each packet.\n" \
            "--help -h => Show help menu information.\n", argv[0]);

        exit(0);
    }
    // 检查是否设置了接口参数。
    if (g_info.interface == NULL)
    {
        fprintf(stderr, "Missing --dev option.\n");

        exit(1);
    }

    //检查是否设置了目标IP参数。
    if (g_info.dIP == NULL)
    {
        fprintf(stderr, "Missing --dst option\n");

        exit(1);
    }

    // 创建线程标识符集
    pthread_t pid[g_info.threads];

    // 开始发送时间
    startTime = time(NULL);

    // 循环每个线程。
    for (uint16_t i = 0; i < g_info.threads; i++)
    {
        // 创建新的pthread_info结构以传递给线程，并将g_info复制到info。
        struct pthread_info* info = (struct pthread_info*)malloc(sizeof(struct pthread_info));
        memcpy(info, &g_info, sizeof(struct pthread_info));
        
        // 如果设定了自定义有效负载
        if (info->payloadStr != NULL)
        {
            // 按空格分割参数。
            char* split;

            // 构建临时字符串
            char* str = (char*)malloc((strlen(info->payloadStr) + 1) * sizeof(char));
            strcpy(str, info->payloadStr);

            //以空格进行切割 每次只返回被切割的第一个字串
            split = strtok(str, " ");

            while (split != NULL)
            {
                //格式化数据(以一个字节char类型的十六进制)放入payload中 
                sscanf(split, "%2hhx", &info->payload[info->payloadLength]);

                info->payloadLength++;

                split = strtok(NULL, " ");
            }

            // 释放临时字符串
            free(str);
        }
        // 创建线程
        if (pthread_create(&pid[i], NULL, threadHndl, (void*)info) != 0)
        {
            fprintf(stderr, "Error spawning thread %" PRIu16 "...\n", i);
        }
    }
    // 捕捉Ctrl+C信号.
    signal(SIGINT, signalHndl);

    // Loop!
    while (cont)
    {
        sleep(1);
    }

    // 结束时间.
    time_t endTime = time(NULL);

    // 稍等片刻进行清理。.
    sleep(1);

    // 统计数字
    time_t totalTime = endTime - startTime;

    fprintf(stdout, "Finished in %lu seconds.\n\n", totalTime);

    if (!g_info.nostats)
    {
        uint64_t pps = pcktCount / (uint64_t)totalTime;
        uint64_t MBTotal = totalData / 1000000;
        uint64_t MBsp = (totalData / (uint64_t)totalTime) / 1000000;
        uint64_t mbTotal = totalData / 125000;
        uint64_t mbps = (totalData / (uint64_t)totalTime) / 125000;

        // Print statistics.
        fprintf(stdout, "Packets Total => %" PRIu64 ".\nPackets Per Second => %" PRIu64 ".\n\n", pcktCount, pps);
        fprintf(stdout, "Megabytes Total => %" PRIu64 ".\nMegabytes Per Second => %" PRIu64 ".\n\n", MBTotal, MBsp);
        fprintf(stdout, "Megabits Total => %" PRIu64 ".\nMegabits Per Second => %" PRIu64 ".\n\n", mbTotal, mbps);
    }

    // Exit program successfully.
    exit(0);
}