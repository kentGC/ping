#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <setjmp.h>
#include <errno.h>
#include <sys/select.h>
#include <fcntl.h>
#define LOGE printf
/*
*Descrition:cal packet check sum 
*Param:
*    buffer:Calculating the content cache of the checksum
*    size:buffer size
*Return：
*    checksum
*/
unsigned short checksum(unsigned short *buffer, int size)
{
	if (NULL == buffer)
		return 0;
    unsigned long cksum = 0;
	/*Calculate and in short memory*/
    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }
	
    if (size) {
        cksum += *(unsigned char*)buffer;
    }
	/*Make sure the end result is short*/
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    /*Negative return*/
    return (unsigned short)(~cksum);
}
/*
*Descrition:send a ping to ip ,timeout 3 second
*Param:
*    ip:IP of network byte order
*Return:
*    recv icmp reply from host success return true ,failed return false 
*    
*/
bool icmp_send(in_addr_t ip)
{  
#define PACKET_SIZE 512
#define RECV_TIEMOUT 3 
    int n = 0;
    int socket_fd = 0;
    int len = 0;
    bool res = false;
    static unsigned int seq = 0;
    struct protoent *protocol = NULL;
    struct sockaddr_in addr;
    struct ip* iphdr = NULL;
    char packet[PACKET_SIZE];
    struct timeval timer;
	
    memset(&timer, 0x0, sizeof(struct timeval));
	
    timer.tv_sec = RECV_TIEMOUT;
    
    struct icmp *icmp;

    struct sockaddr_in from;

    memset(&packet, 0x0, sizeof(packet));
    memset(&addr, 0x0, sizeof(struct sockaddr_in));
    /*get icmp protocol*/
    protocol = getprotobyname("icmp");
    if (NULL == protocol)
        return res;
    /*set socketaddr*/
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip;

    icmp=(struct icmp*)packet;
    /*set icmp pacaket header*/
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code=0;
    icmp->icmp_cksum=0;
    icmp->icmp_seq = seq++;
    icmp->icmp_id=getpid();
    
    len = sizeof(struct ip) + sizeof(struct icmp) + sizeof(struct timeval);
    /*add current time to packet data*/
    gettimeofday((struct timeval *)icmp->icmp_data,NULL);

    icmp->icmp_cksum=checksum((unsigned short *)icmp,len);

    socket_fd = socket(AF_INET, SOCK_RAW, protocol->p_proto/*IPPROTO_ICMP*/);
    if (0 > socket_fd){
		LOGE("LEDM:Create socket error(%d:%s)", errno, strerror(errno));
        return res;
    }
	
    if (-1 != sendto(socket_fd, packet, len, 0,(struct sockaddr *)&addr, sizeof(struct sockaddr_in)))
	{

        len = sizeof(from);
        memset(packet,0x0,sizeof(packet));
	    /*set recv timeout*/
        setsockopt(socket_fd,SOL_SOCKET,SO_RCVTIMEO,&timer,sizeof(timer));
        if (-1 != recvfrom(socket_fd, packet,sizeof(packet), 0, (struct sockaddr *)&from, (socklen_t *)&len))
        {
            iphdr = (struct ip*)packet;
            icmp = (struct icmp*)(packet + (iphdr->ip_hl << 2));
            /*Verify ICMP reply*/
            if (icmp->icmp_type == ICMP_ECHOREPLY && icmp->icmp_id == getpid())
                res = true;
		}
        else
        {
			if (EAGAIN != errno)
			    LOGE("LEDM:recv icmp faild(%d:%s)", errno, strerror(errno));
		}			
    }
	else 
	{
		LOGE("LEDM:Send icmp faild(%d:%s)", errno, strerror(errno));
	}
    close(socket_fd);
    return res;
#undef PACKET_SIZE 
#undef RECV_TIEMOUT 
}

#define NTP_DOMAIN "ntp.org"  /*ping ntp server*/
/*
*Descrition:DNS resolve 
*Param:
*    domain:domain str 
*    iplist:IP net list of DNS resolution
*    count:buffer size
*Return:
*    Number of IP resolved
*/
static int domain_resolution(const char *domain, in_addr_t *iplist, unsigned int count)
{
    int fd=0;
    int i = 0;
    struct addrinfo *result = NULL;
    struct addrinfo *loop = NULL;
    struct addrinfo hints;
    int err;

    if(NULL == domain || NULL == iplist)
        return -1;

    memset(&hints, 0, sizeof(addrinfo));

    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;
    /*get ip from domain*/
    if((err = getaddrinfo(domain, NULL, &hints, &result)) != 0){
        LOGE("LEDM:Domain resolve failed(%d:%s)", err, gai_strerror(err));
        return -1;
    }
    
    for (loop = result; loop != NULL && i < count ; loop = loop->ai_next, i++) {
        iplist[i] = ((sockaddr_in*)(loop->ai_addr))->sin_addr.s_addr;
    }

    freeaddrinfo(result);
    return i;
}
/*
*Descrition:DNS resolve 
*Param:
*    domain:domain str 
*    iplist:IP net list of DNS resolution
*    count:buffer size
*Return:
*    Number of IP resolved
*/
static bool internet_check(void)
{   
    static in_addr_t iplist[256]; 
    static int count = 0;

    int i = 0;
    memset(&iplist, 0x0, sizeof(iplist));

    count = domain_resolution(NTP_DOMAIN,iplist,sizeof(iplist)/sizeof(iplist[0]));
    if (0 >= count){
		LOGE("LEDM:Domain resolve failed(No ip from domain)");
        return false;
    }
    for (i = 0; i < count; i++)
    {
        if(icmp_send(iplist[i]))
            return true;
    }

    LOGE("LEDM:Internet Disconnect");
    return false;
}
int main()
{
    if(true == internet_check())
	printf("haha\n");

}
