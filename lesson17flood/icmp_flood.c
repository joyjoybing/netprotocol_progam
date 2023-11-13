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

// ȫ�ֱ���
uint8_t cont = 1;
time_t startTime;
volatile uint64_t pcktCount = 0;    //��������
volatile uint64_t totalData = 0;    //���͵��ֽ���������


void parse_command_line(int argc, char* argv[]);    //������




#define MAX_PCKT_LENGTH 0xFFFF  //�������ֵ
//�߳̽ṹ
struct pthread_info {
    char* interface;    //�ӿ�
    char* sIP;          //ԴIP
    char* dIP;          //Ŀ��IP
    uint16_t port;      //Ŀ�Ķ˿�
    uint16_t sport;     //Դ�˿�
    uint64_t interval;  //��΢��Ϊ��λ�������ݰ��ļ��
    uint16_t min;       //��С��Ч���س���
    uint16_t max;       //�����Ч���س���
    uint64_t pcktCountMax;  //�����͵�������ݰ�����
    time_t seconds;         //��
    uint8_t payload[MAX_PCKT_LENGTH];   //��Ч�غɵ����ֵ����
    char* payloadStr;       //��Ч����ֵ
    uint16_t payloadLength; //��Ч���س���                    
    int icmp;
    int verbose;    //��ӡÿ�η��͵���������
    int internal;   //����ʱ�����δָ��ԴIP��������10.0���������ԴIP��0.0 / 8��Χ��
    int nostats;    //������PPS�ʹ�������ܻ�������ܡ�
    int icmp_type;
    int icmp_code;
    int help;
    uint8_t sMAC[ETH_ALEN];
    uint8_t dMAC[ETH_ALEN];
    uint16_t threads;   //�߳�����
    int nocsum;         //������IP��ͷ��У��͡�������Ӳ���ϵ�У���ж�أ��Ӷ�������ܡ�
    int nocsum4;        //�������4���У��ͣ�����TCP/UDP���������ڱ����н�У����ֶα���Ϊ0��
    uint8_t minTTL; //���TTLֵ
    uint8_t maxTTL; //��СTTLֵ
    uint8_t tos;    //��������

    time_t startingTime;
    uint16_t id;    //���ṹID
}g_info;


void signalHndl(int tmp)
{
    cont = 0;
}

uint16_t randNum(uint16_t min, uint16_t max, unsigned int seed)
{
    return (rand_r(&seed) % (max - min + 1)) + min;
}

// ������ѡ��
static struct option longoptions[] =
{
    {"dev", required_argument, NULL, 'i'},//����������NULLʱ�����ص��Ĳ�����ֵ
    {"src", required_argument, NULL, 's'},
    {"dst", required_argument, NULL, 'd'},
    {"port", required_argument, NULL, 'p'},
    {"sport", required_argument, NULL, 14},//�������������Ϊ�գ�\
                                            ��ô��ѡ��ĳ����ѡ���ʱ��getopt_long������0�����ҽ�flagָ�����ָ��valֵ��
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

    // ���������С�
    while (optind < argc)   //optind:��һ�����������Ĳ�����argv�е��±�ֵ
    {
        if ((c = getopt_long(argc, argv, "i:d:t:vhs:p:c:", longoptions, NULL)) != -1)
        {
            switch (c)
            {
            case 'i':
                g_info.interface = optarg;  //optarg:��ʾ��ǰѡ���Ӧ�Ĳ���ֵ��

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
                g_info.interval = strtoll(optarg, NULL, 10);//�ַ���ת����long long int���͵�10������

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

    // �����߳̽ṹinfo.
    struct pthread_info* info = (struct pthread_info*)data;

    // ���� sockaddr_ll struct.
    struct sockaddr_ll sin;

    // Fill out sockaddr_ll struct.
    sin.sll_family = PF_PACKET;//PF_PACKET�����ó����ѡ���\
                               ���������յ����ݰ�����ֱ�Ӵ��͵�Ӧ�ó�����������ں˴���
    //�ѽӿ�ת�ɶ�Ӧ��������
    sin.sll_ifindex = if_nametoindex(info->interface);   /* �ӿ����� */
    sin.sll_protocol = htons(ETH_P_IP);     //һ����IP�Ļ�ѡETH_P_IP
    sin.sll_halen = ETH_ALEN;    /* ��ַ���� */ 

   
    //����ԭʼ�׽���
    int sockfd;
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
        perror("socket");

        pthread_exit(NULL);
    }


        // ���սӿڵ�MAC��ַ��ԴMAC����
        struct ifreq ifr;
        strcpy(ifr.ifr_name, info->interface);

        // ���Ի�ȡMAC��ַ��
        if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) != 0)
        {
            perror("ioctl");

            pthread_exit(NULL);
        }

        // ��ifr�е�MAC����sMAC��
        memcpy(info->sMAC, ifr.ifr_addr.sa_data, ETH_ALEN);

    //��sMAC�����׽��ֵ�MAC��
    memcpy(sin.sll_addr, info->sMAC, ETH_ALEN);

    // ���԰��׽��֡�
    if (bind(sockfd, (struct sockaddr*)&sin, sizeof(sin)) != 0)
    {
        perror("bind");

        pthread_exit(NULL);
    }

    while (1)
    {
        uint16_t offset = 0;    //ƫ������0
        // �����������
        unsigned int seed;
        if (info->nostats)
        {
            seed = time(NULL) ^ getpid() ^ pthread_self();
        }
        else
        {
            seed = (unsigned int)(pcktCount + info->id);
        }

        // ��ȡԴ�˿ڣ��������
        uint16_t srcPort;

        // ���Դ�˿��Ƿ�Ϊ0���������
        if (info->sport == 0)
        {
            srcPort = randNum(1024, 65535, seed);
        }
        else
        {
            srcPort = info->sport;
        }

        // ��ȡĿ��˿ڡ�
        uint16_t dstPort;

        // ���Ŀ�Ķ˿��Ƿ�Ϊ0���������
        if (info->port == 0)
        {
            dstPort = randNum(10, 65535, seed);
        }
        else
        {
            dstPort = info->port;
        }


        //����ip
        char IP[32];

        //�Ƿ�ָ��ԴIP
        if (info->sIP == NULL)
        {
            // ��ԴIP��ƭΪ�κ�IP��ַ��
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

        // ��ʼ�����ݰ�������

        char buffer[MAX_PCKT_LENGTH];

        // ������̫����ͷ��
        struct ethhdr* eth = (struct ethhdr*)(buffer);

        // ��д��̫����ͷ��
        eth->h_proto = htons(ETH_P_IP);
        memcpy(eth->h_source, info->sMAC, ETH_ALEN);
        memcpy(eth->h_dest, info->dMAC, ETH_ALEN);


        // ������̫�����ֵ�ƫ������
        offset += sizeof(struct ethhdr);

        // ����IPͷ��
        struct iphdr* iph = (struct iphdr*)(buffer + offset);

        //���IP��ͷ
        iph->ihl = 5;   //IP��ͷ��С
        iph->version = 4;   //��ַ�汾
        iph->protocol = IPPROTO_ICMP;
        iph->id = 0;
        iph->frag_off = 0;  //�ֶ�ƫ��
        iph->saddr = inet_addr(IP);
        iph->daddr = inet_addr(info->dIP);
        iph->tos = info->tos;

        iph->ttl = (uint8_t)randNum(info->minTTL, info->maxTTL, seed);

        // ����IP��ͷ��ƫ����
        offset += sizeof(struct iphdr);


        // ������Ч�غɳ��Ⱥ���Ч�غɡ�
        uint16_t dataLen;  //��Ч�غɳ��� 

        uint16_t l4header;  //ICMP��ͷ��ƫ����

        l4header = sizeof(struct icmphdr);



        //  ����ICMP��ͷ��ƫ����
        offset += l4header;

        unsigned char* data = (unsigned char*)(buffer + offset);

        //����Զ�����Ч���ء�
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
            // ������ַ���д��Ч���ء�
            dataLen = randNum(info->min, info->max, seed);

            //������Ч���ش�С
            for (uint16_t i = 0; i < dataLen; i++)
            {
                *data = rand_r(&seed);
                *data++;
            }
        }
        // ��Сƫ��������Ϊ���ǽ����ص�L4�������䡣
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
     
      

        uint16_t pcktlen = 0; //������

        //����IPͷ�ĳ��Ⱥ�У��͡�
        pcktlen = sizeof(struct iphdr) + l4header + dataLen;

        iph->tot_len = htons(pcktlen);  //IP����

        if (!info->nocsum)
        {
            update_iph_checksum(iph);
        }

        // ��ʼ����ʾ�ѷ����������ı�����
        uint16_t sent;

        //���Է������ݡ�
        if ((sent = sendto(sockfd, buffer, pcktlen + sizeof(struct ethhdr), 0, (struct sockaddr*)&sin, sizeof(sin))) < 0)
        {
            perror("send");

            continue;
        }
       
        // ������ã�����ӵ�ͳ����Ϣ��
        if (!info->nostats)
        {
            __sync_add_and_fetch(&totalData, sent);
        }

        if (!info->nostats || info->pcktCountMax > 0)
        {
            // ��������
            if (__sync_add_and_fetch(&pcktCount, 1) >= info->pcktCountMax && info->pcktCountMax > 0)
            {
                cont = 0;

                break;
            }
        }

        // �Ƿ��ӡ���͵���������
        if (info->verbose)
        {
            fprintf(stdout, "Sent %d bytes to destination. (%" PRIu64 "/%" PRIu64 ")\n", sent, pcktCount, info->pcktCountMax);
        }

        // ���ʱ�䷵��ֵ��
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

        // ��������Ƿ�Ӧ�������ݰ�֮��ȴ���
        if (info->interval > 0)
        {
            usleep(info->interval);
        }
    }

    // �ر� socket.
    close(sockfd);

    // Free information.
    free(info);

    // Exit thread.
    pthread_exit(NULL);
}



int main(int argc, char* argv[])
{
    // ����Ĭ��ֵ
    g_info.threads = get_nprocs(); //���ؿ���CPU����

    g_info.minTTL = 64;
    g_info.maxTTL = 64;
    g_info.interval = 1000000;  //��΢��Ϊ��λ�������ݰ��ļ��
    g_info.tos = 0;

    g_info.startingTime = time(NULL);   //��ʼʱ��

    // Parse the command line.
    parse_command_line(argc, argv);

    // ����Ƿ������˰�����־������ǣ����ӡ������Ϣ��
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
    // ����Ƿ������˽ӿڲ�����
    if (g_info.interface == NULL)
    {
        fprintf(stderr, "Missing --dev option.\n");

        exit(1);
    }

    //����Ƿ�������Ŀ��IP������
    if (g_info.dIP == NULL)
    {
        fprintf(stderr, "Missing --dst option\n");

        exit(1);
    }

    // �����̱߳�ʶ����
    pthread_t pid[g_info.threads];

    // ��ʼ����ʱ��
    startTime = time(NULL);

    // ѭ��ÿ���̡߳�
    for (uint16_t i = 0; i < g_info.threads; i++)
    {
        // �����µ�pthread_info�ṹ�Դ��ݸ��̣߳�����g_info���Ƶ�info��
        struct pthread_info* info = (struct pthread_info*)malloc(sizeof(struct pthread_info));
        memcpy(info, &g_info, sizeof(struct pthread_info));
        
        // ����趨���Զ�����Ч����
        if (info->payloadStr != NULL)
        {
            // ���ո�ָ������
            char* split;

            // ������ʱ�ַ���
            char* str = (char*)malloc((strlen(info->payloadStr) + 1) * sizeof(char));
            strcpy(str, info->payloadStr);

            //�Կո�����и� ÿ��ֻ���ر��и�ĵ�һ���ִ�
            split = strtok(str, " ");

            while (split != NULL)
            {
                //��ʽ������(��һ���ֽ�char���͵�ʮ������)����payload�� 
                sscanf(split, "%2hhx", &info->payload[info->payloadLength]);

                info->payloadLength++;

                split = strtok(NULL, " ");
            }

            // �ͷ���ʱ�ַ���
            free(str);
        }
        // �����߳�
        if (pthread_create(&pid[i], NULL, threadHndl, (void*)info) != 0)
        {
            fprintf(stderr, "Error spawning thread %" PRIu16 "...\n", i);
        }
    }
    // ��׽Ctrl+C�ź�.
    signal(SIGINT, signalHndl);

    // Loop!
    while (cont)
    {
        sleep(1);
    }

    // ����ʱ��.
    time_t endTime = time(NULL);

    // �Ե�Ƭ�̽�������.
    sleep(1);

    // ͳ������
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