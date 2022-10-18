#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>

int main(int args, char**argv){
    int sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));//give the entire packets, not just data. Third parameter specifies the connection to be active on

    struct sockaddr_ll addr;
    struct sockaddr_ll listenaddr;
    listenaddr.sll_family = AF_PACKET;
    listenaddr.sll_protocol = htons(ETH_P_ALL);
    listenaddr.sll_ifindex = if_nametoindex("h1-eth0");//which hardware interface to listen on

    bind(sockfd, (struct sockaddr*)&listenaddr, sizeof(listenaddr));

    while(1){
        socklen_t len = sizeof(addr);
        char buf[5000];
        int n = recvfrom(sockfd, buf, 5000, 0, (struct sockaddr*) &addr, &len);

        if((addr.sll_pkttype != PACKET_OUTGOING)){//filter out outgoing packets
            printf("Got a packet\n");
            struct ether_header eh;
            memcpy(&eh, buf, 14);
            printf("Destination: %s\nSource: %s\nType: %s\n",
                   ether_ntoa((struct ether_addr* ) &eh.ether_dhost), ether_ntoa((struct ether_addr* ) &eh.ether_shost), ether_ntoa((struct ether_addr* ) &eh.ether_type));
                   if(ntohs(eh.ether_type) == 0x0800) {
   	printf("IPv4 Packet\n");
           struct iphdr iph;
           struct in_addr ina;
           memcpy(&iph, &buf[14], sizeof(iph));
           ina.s_addr = iph.saddr;
           printf("Source : %s\n", inet_ntoa(ina));
           ina.s_addr = iph.daddr;
           printf("Destination : %s\n", inet_ntoa(ina));
        }
        }
    }
}