#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <errno.h>
#include <unistd.h>
#include <sys/select.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>

unsigned short checksum(void *b, int len);

struct icmp_header
{
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t id;
  uint16_t seqnum;
};

int main()
{
  int packet_socket[10];
  fd_set myfds;
  // get list of interface addresses. This is a linked list. Next
  // pointer is in ifa_next, interface name is in ifa_name, address is
  // in ifa_addr. You will have multiple entries in the list with the
  // same name, if the same interface has multiple addresses. This is
  // common since most interfaces will have a MAC, IPv4, and IPv6
  // address. You can use the names to match up which IPv4 address goes
  // with which MAC address.
  struct ifaddrs *ifaddr, *tmp, *interfaceAddr;
  struct ifreq ifr;
  char macp[INET6_ADDRSTRLEN];
  if (getifaddrs(&ifaddr) == -1)
  {
    perror("getifaddrs");
    return 1;
  }
  int counter = 0;
  char buffer[1024];
  int index = 0;
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
      // if (!strncmp(&(tmp->ifa_name[3]), "eth1", 4))
      // {
      printf("Creating Socket on interface %s\n", tmp->ifa_name);
      //  create a packet socket
      //  AF_PACKET makes it a packet socket
      //  SOCK_RAW makes it so we get the entire packet
      //  could also use SOCK_DGRAM to cut off link layer header
      //  ETH_P_ALL indicates we want all (upper layer) protocols
      //  we could specify just a specific one
      packet_socket[index] = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
      struct sockaddr_ll *s = (struct sockaddr_ll *)(tmp->ifa_addr);
      int i;
      int len = 0;
      for (i = 0; i < 6; i++)
      {
        len += sprintf(macp + len, "%02X%s", s->sll_addr[i], i < 5 ? ":" : "");
      }
      printf("Interface name : %s\n Interface Address : %s\n", (ifaddr)->ifa_name, macp);
      printf("Mac and macp size: %s %ld\n", macp, sizeof(macp));
      memcpy(&buffer[counter], macp, sizeof(macp));
      printf("Buffer mac at %d: %s\n", counter, &buffer[counter]);
      counter += 46;

      char *ip;
      ifr.ifr_ifru.ifru_addr.sa_family = AF_INET;
      strncpy(ifr.ifr_name, tmp->ifa_name, IFNAMSIZ - 1);
      ioctl(packet_socket[index], SIOCGIFADDR, &ifr);
      ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_ifru.ifru_addr)->sin_addr);
      printf("Ip and ip size : %s %ld\n", ip, sizeof(ip));
      memcpy(&buffer[counter], ip, sizeof(ip));
      printf("Buffer ip at %d: %s\n", counter, &buffer[counter]);
      counter += 8;
      if (packet_socket[index] < 0)
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
      if (bind(packet_socket[index], tmp->ifa_addr, sizeof(struct sockaddr_ll)) == -1)
      {
        perror("bind");
      }
      else
      {
        FD_SET(packet_socket[index], &myfds);
        FD_SET(STDIN_FILENO, &myfds);
      }
      index++;
      // }
    }
  }

  // loop and recieve packets. We are only looking at one interface,
  // for the project you will probably want to look at more (to do so,
  // a good way is to have one socket per interface and use select to
  // see which ones have data) *** look at udpselect.c line 20 - 26
  printf("Ready to recieve now\n");
  while (1)
  {

    char buf[1500];
    fd_set fdstmp = myfds;
    int nn = select(FD_SETSIZE, &fdstmp, NULL, NULL, NULL);
    struct sockaddr_ll recvaddr;
    unsigned int recvaddrlen = sizeof(struct sockaddr_ll);
    for (int j = 0; j < 10; ++j)
    {

      if (FD_ISSET(packet_socket[j], &fdstmp))
      {
        // we can use recv, since the addresses are in the packet, but we
        // use recvfrom because it gives us an easy way to determine if
        // this packet is incoming or outgoing (when using ETH_P_ALL, we
        // see packets in both directions. Only outgoing can be seen when
        // using a packet socket with some specific protocol)
        int n = recvfrom(packet_socket[j], buf, 1500, 0, (struct sockaddr *)&recvaddr, &recvaddrlen);
        printf("Packet socket after receive: %d\n\n", packet_socket[j]);
        printf("Got a %d byte packet\n", n);
        char temp_buf[n];
        printf("Size of temp buf now: %ld\n", sizeof(temp_buf));

        // ignore outgoing packets (we can't disable some from being sent
        // by the OS automatically, for example ICMP port unreachable
        // messages, so we will just ignore them here)
        if (recvaddr.sll_pkttype == PACKET_OUTGOING)
          continue;
        // start processing all others
        struct ether_header eh;
        eh.ether_type = ntohs(0x0000);
        memcpy(&eh, buf, 14);

        if (ntohs(eh.ether_type) == 0x0800)
        {
          printf("ICMP\n\n");
          struct icmp_header icmp;
          struct iphdr iph, iphResponse;
          struct ether_header ehResponse;

          // build IP portion
          memcpy(&iph, &buf[14], sizeof(iph));

          memcpy(&iphResponse, &iph, sizeof(iph));

          memcpy(&iphResponse.saddr, &iph.daddr, sizeof(iph.daddr));
          memcpy(&iphResponse.daddr, &iph.saddr, sizeof(iph.saddr));
          // build EH portion
          memcpy(ehResponse.ether_dhost, eh.ether_shost, sizeof(eh.ether_shost));
          memcpy(ehResponse.ether_shost, eh.ether_dhost, sizeof(eh.ether_dhost));
          memcpy(&ehResponse.ether_type, &eh.ether_type, sizeof(eh.ether_type));

          memcpy(&icmp, &buf[34], sizeof(icmp));
          printf("Temp buf size: %ld\n", sizeof(temp_buf));
          // Verify checksum
          // Sequence num is the ttl -- 32 hops and done.  Decrement/Increment ?? if we hit 0, drop packet, and send ICMP time exceeded message.
          printf("ICMP Struct type: %hhu, code: %hhu, checksum: %hhu, id: %hhu, sequence number: %hhu \n", icmp.type, icmp.code, icmp.checksum, icmp.id, icmp.seqnum);
          icmp.type = ntohs(0x0000);
          icmp.checksum = 0;

          printf("ICMP Struct type: %hhu, code: %hhu, checksum: %hhu, id: %hhu, sequence number: %hhu \n", icmp.type, icmp.code, icmp.checksum, icmp.id, icmp.seqnum);

          memcpy(&temp_buf, &ehResponse, sizeof(ehResponse));
          memcpy(&temp_buf[14], &iphResponse, sizeof(iphResponse));
          memcpy(&temp_buf[34], &icmp, sizeof(icmp));
          // Data - size of data is hard coded, so def need to change.
          memcpy(&temp_buf[42], &buf[42], n - 42);

          icmp.checksum = checksum(&temp_buf[14], n - 14);

          memcpy(&temp_buf[36], &icmp.checksum, 2);
          int success = send(packet_socket[j], temp_buf, n, 0);
          if (success == -1)
          {
            perror("sendto():");
            exit(90);
          }
        }
        // when an ARP request is processed, respond
        else if (ntohs(eh.ether_type) == 0x0806)
        {
          char temp_mac[INET6_ADDRSTRLEN];

          printf("Packet socket in ARP Request: %d\n\n", packet_socket[j]);
          printf("Received Ether Destination: %s\n", ether_ntoa((struct ether_addr *)&eh.ether_dhost));
          printf("Received Ether Source: %s\n", ether_ntoa((struct ether_addr *)&eh.ether_shost));
          printf("Received Ether Type: %s\n", ether_ntoa((struct ether_addr *)&eh.ether_type));

          struct ether_arp arpReceived, arpResponse;
          memcpy(&arpReceived, &buf[14], sizeof(arpReceived));

          for (int i = 0; i < sizeof(buffer); i += 54)
          {
            // printf("Got into for loop\n");
            // printf("Buffer at %d: %s\n", i, &buffer[i]);
            // printf("IP at %d: %s\n", i + 46, &buffer[i + 46]);
            // struct sockaddr_in sa;
            char temp_ip[9];
            char temp_tip[INET_ADDRSTRLEN];
            strncpy(temp_ip, &buffer[i + 46], 8);
            // memcpy(&temp_ip, &buffer[i + 46], 8);
            printf("IP %s\n", temp_ip);
            inet_ntop(AF_INET, &(arpReceived.arp_tpa), temp_tip, INET_ADDRSTRLEN);
            // temp_tip = inet_ntoa((struct in_addr) & arpReceived.arp_tpa);
            // memcpy(temp_arp.arp_tpa, &buffer[i + 46], 8);
            printf("TIP %s\n", temp_tip);
            if (!strcmp(temp_ip, temp_tip))
            {
              printf("Got here\n");
              memcpy(&temp_mac, &buffer[i], 46);
              break;
            }
          }
          printf("Mac in ARP: %s\n", temp_mac);

          arpResponse = arpReceived;
          arpResponse.ea_hdr.ar_op = htons(2);

          // create ARP packet to the request with previous information and host MAC address
          memcpy(arpResponse.arp_tha, arpReceived.arp_sha, sizeof(arpReceived.arp_sha));
          memcpy(arpResponse.arp_tpa, arpReceived.arp_spa, sizeof(arpReceived.arp_spa));
          memcpy(arpResponse.arp_spa, arpReceived.arp_tpa, sizeof(arpReceived.arp_tpa));
          memcpy(arpResponse.arp_sha, ether_aton(temp_mac), 6);

          struct ether_header ehResponse;

          memcpy(ehResponse.ether_dhost, eh.ether_shost, sizeof(eh.ether_shost));
          memcpy(ehResponse.ether_shost, arpResponse.arp_sha, 6);
          memcpy(&ehResponse.ether_type, &eh.ether_type, sizeof(eh.ether_type));

          printf("Size of eh Response: %ld\n\n", sizeof(ehResponse));
          memcpy(&temp_buf[0], &ehResponse, sizeof(ehResponse));
          memcpy(&temp_buf[14], &arpResponse, sizeof(arpResponse));

          printf("Response Ether Destination: %s\n", ether_ntoa((struct ether_addr *)&ehResponse.ether_dhost));
          printf("Response Ether Source: %s\n", ether_ntoa((struct ether_addr *)&ehResponse.ether_shost));
          printf("Response Ether Type: %s\n\n", ether_ntoa((struct ether_addr *)&ehResponse.ether_type));

          int success = send(packet_socket[j], temp_buf, n, 0);
          if (success == -1)
          {
            perror("send():");
            exit(90);
          }

          uint16_t reset = 0x0;
          memcpy(&eh.ether_type, &reset, sizeof(eh.ether_type));
        }
      }
      if (FD_ISSET(STDIN_FILENO, &fdstmp))
      {
        printf("The user typed something, I better do something with it\n");
        char buf[5000];
        fgets(buf, 5000, stdin);
        printf("You typed %s\n", buf);
      }
    }
    // what else to do is up to you, you can send packets with send,
    // just like we used for TCP sockets (or you can use sendto, but it
    // is not necessary, since the headers, including all addresses,
    // need to be in the buffer you are sending)
  }
  // free the interface list when we don't need it anymore
  freeifaddrs(ifaddr);
  freeifaddrs(tmp);
  freeifaddrs(interfaceAddr);
  for (int j = 0; j < 10; ++j)
    close(packet_socket[j]);

  // exit
  return 0;
}

// Function to calculate checksum
// We used the code from this geeks-for-geeks article
// as the basis of our function:
// https://www.geeksforgeeks.org/ping-in-c/
unsigned short checksum(void *b, int len)
{
  unsigned short *buf = b;
  unsigned int sum = 0;
  unsigned short result;

  for (sum = 0; len > 1; len -= 2)
    sum += *buf++;
  if (len == 1)
    sum += *(unsigned char *)buf;
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  result = ~sum;
  return result;
}
