#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <stdio.h>
//#include <errno.h>
//#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
//#include <net/if.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

int main()
{
  int packet_socket;
  // get list of interface addresses. This is a linked list. Next
  // pointer is in ifa_next, interface name is in ifa_name, address is
  // in ifa_addr. You will have multiple entries in the list with the
  // same name, if the same interface has multiple addresses. This is
  // common since most interfaces will have a MAC, IPv4, and IPv6
  // address. You can use the names to match up which IPv4 address goes
  // with which MAC address.
  struct ifaddrs *ifaddr, *tmp;
  if (getifaddrs(&ifaddr) == -1)
  {
    perror("getifaddrs");
    return 1;
  }
  // have the list, loop over the list
  for (tmp = ifaddr; tmp != NULL; tmp = tmp->ifa_next)
  {
    // Check if this is a packet address, there will be one per
    // interface.  There are IPv4 and IPv6 as well, but we don't care
    // about those for the purpose of enumerating interfaces. We can
    // use the AF_INET addresses in this list for example to get a list
    // of our own IP addresses
    if (tmp->ifa_addr->sa_family == AF_PACKET)
    {
      printf("Interface: %s\n", tmp->ifa_name);
      // create a packet socket on interface r?-eth1
      if (!strncmp(&(tmp->ifa_name[3]), "eth1", 4))
      {
        printf("Creating Socket on interface %s\n", tmp->ifa_name);
        // create a packet socket
        // AF_PACKET makes it a packet socket
        // SOCK_RAW makes it so we get the entire packet
        // could also use SOCK_DGRAM to cut off link layer header
        // ETH_P_ALL indicates we want all (upper layer) protocols
        // we could specify just a specific one
        packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (packet_socket < 0)
        {
          perror("socket");
          return 2;
        }
        // Bind the socket to the address, so we only get packets
        // recieved on this specific interface. For packet sockets, the
        // address structure is a struct sockaddr_ll (see the man page
        // for "packet"), but of course bind takes a struct sockaddr.
        // Here, we can use the sockaddr we got from getifaddrs (which
        // we could convert to sockaddr_ll if we needed to)
        if (bind(packet_socket, tmp->ifa_addr, sizeof(struct sockaddr_ll)) == -1)
        {
          perror("bind");
        }
      }
    }
  }
  // loop and recieve packets. We are only looking at one interface,
  // for the project you will probably want to look at more (to do so,
  // a good way is to have one socket per interface and use select to
  // see which ones have data) *** look at udpselect.c line 20 - 26
  printf("Ready to recieve now\n");
  while (1)
  {
    char buf[1500], temp_buf[1500];
    struct sockaddr_ll recvaddr;
    unsigned int recvaddrlen = sizeof(struct sockaddr_ll);
    // we can use recv, since the addresses are in the packet, but we
    // use recvfrom because it gives us an easy way to determine if
    // this packet is incoming or outgoing (when using ETH_P_ALL, we
    // see packets in both directions. Only outgoing can be seen when
    // using a packet socket with some specific protocol)
    int n = recvfrom(packet_socket, buf, 1500, 0, (struct sockaddr *)&recvaddr, &recvaddrlen);
    // ignore outgoing packets (we can't disable some from being sent
    // by the OS automatically, for example ICMP port unreachable
    // messages, so we will just ignore them here)
    if (recvaddr.sll_pkttype == PACKET_OUTGOING)
      continue;
    // start processing all others
    printf("Got a %d byte packet\n", n);
    struct ether_header eh;
    memcpy(&eh, buf, 14);
    printf("Destination: %s\nSource: %s\nType: %s\n",
           ether_ntoa((struct ether_addr *)&eh.ether_dhost), ether_ntoa((struct ether_addr *)&eh.ether_shost), ether_ntoa((struct ether_addr *)&eh.ether_type));
    // when an ARP request is processed, respond
    if (ntohs(eh.ether_type) == 0x0806)
    {
      /*printf("IPv4 Packet\n");
      struct iphdr iph;
      struct in_addr ina;
      memcpy(&iph, &buf[14], sizeof(iph));
      ina.s_addr = iph.saddr;
      printf("Source : %s\n", inet_ntoa(ina));
      ina.s_addr = iph.daddr;
      printf("Destination : %s\n", inet_ntoa(ina));
      */
      struct ether_arp arpReceived;
      memcpy(&arpReceived, &buf[14], sizeof(arpReceived));
      // printf("Source Mac : %s\nSource IP : %s\nDestination Mac : %s\nDestination IP :%s", arpReceived.arp_sha, arpReceived.arp_spa, arpReceived.arp_tha, arpReceived.arp_tpa);

      struct in_addr ina;
      // ina.s_addr = arpReceived.arp_sha;
      memcpy(&ina.s_addr, arpReceived.arp_sha, sizeof(arpReceived.arp_sha));
      printf("Source MAC: %s\n", inet_ntoa(ina));
      // ina.s_addr = arpReceived.arp_tha;
      memcpy(&ina.s_addr, arpReceived.arp_tha, sizeof(arpReceived.arp_tha));
      printf("Destination MAC: %s\n", inet_ntoa(ina));
      // ina.s_addr = arpReceived.arp_spa;
      memcpy(&ina.s_addr, arpReceived.arp_spa, sizeof(arpReceived.arp_spa));
      printf("Source IP: %s\n", inet_ntoa(ina));
      // ina.s_addr = arpReceived.arp_tpa;
      memcpy(&ina.s_addr, arpReceived.arp_tpa, sizeof(arpReceived.arp_tpa));
      printf("Destination IP: %s\n", inet_ntoa(ina));

      struct ether_arp arpResponse;
      // create ARP packet to the request with previous information and host MAC address
      memcpy(arpResponse.arp_tha, arpReceived.arp_sha, sizeof(arpReceived.arp_sha));
      memcpy(arpResponse.arp_tpa, arpReceived.arp_spa, sizeof(arpReceived.arp_spa));
      memcpy(arpResponse.arp_spa, arpReceived.arp_tpa, sizeof(arpReceived.arp_tpa));
      memcpy(arpResponse.arp_sha, ifaddr->ifa_name, sizeof(arpReceived.arp_sha));

      memcpy(&temp_buf[14], &arpResponse, sizeof(arpResponse));
      struct ether_header ehResponse;
      memcpy(ehResponse.ether_dhost, eh.ether_shost, sizeof(eh.ether_dhost));
      memcpy(ehResponse.ether_shost, eh.ether_dhost, sizeof(eh.ether_dhost));
      memcpy(&ehResponse.ether_type, &eh.ether_type, sizeof(eh.ether_type));
      memcpy(&temp_buf, &ehResponse, sizeof(ehResponse));
      sendto(packet_socket, temp_buf, 1500, 0,
             (struct sockaddr *)&arpReceived.arp_spa, sizeof(arpReceived.arp_spa));
    }

    // what else to do is up to you, you can send packets with send,
    // just like we used for TCP sockets (or you can use sendto, but it
    // is not necessary, since the headers, including all addresses,
    // need to be in the buffer you are sending)
  }
  // free the interface list when we don't need it anymore
  freeifaddrs(ifaddr);
  // exit
  return 0;
}
