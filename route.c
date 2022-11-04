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

/*
 * Authors: Justin Sorensen, Meghan Harris, and Professor Kalafut
 * Program: Simulate a router receiving ARP and ICMP Echo
 * Request and forwarding respective replies.
 */

// Function to calculate checksum for ICMP
unsigned short checksum(void *b, int len);

// Struct to act as the ICMP header with the
// properties we want: type, code, checksum, id,
// and sequence number
struct icmp_header
{
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t id;
  uint16_t seqnum;
};

// Main program to simulate Router behavior
int main()
{
  // Array to hold multiple sockets
  int packet_socket[10];
  // File descriptor object
  fd_set myfds;
  // Struct to iterate through interfaces
  struct ifaddrs *ifaddr, *tmp;
  // Struct to hold IP address
  struct ifreq ifr;
  // Holds MAC address as string
  char macp[INET6_ADDRSTRLEN];
  // For counting place in buffer
  int counter = 0;
  // Buffer to hold MAC and associated IP
  char routerAddress[1024];
  // Holds the routing table information read in from the txt file
  char device_name[3] = "";
  char routingTable[1024];
  struct ether_header eh, ehResponse, ehRequest;
  struct sockaddr_ll *s;
  struct iphdr iph, iphResponse;
  struct icmp_header icmp;
  // Place to store MAC address
  char temp_mac[INET6_ADDRSTRLEN];
  // Structs to hold our ARP ether information
  struct ether_arp arpReceived, arpResponse, arpRequest;
  // For adding packet_socket elements
  int index = 0;
  char ipAddress[100];
  int ipCounter = 0;
  struct timeval timeout;
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;
  // get list of interface addresses. This is a linked list. Next
  // pointer is in ifa_next, interface name is in ifa_name, address is
  // in ifa_addr. You will have multiple entries in the list with the
  // same name, if the same interface has multiple addresses. This is
  // common since most interfaces will have a MAC, IPv4, and IPv6
  // address. You can use the names to match up which IPv4 address goes
  // with which MAC address.
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
      printf("Creating Socket on interface %s\n", tmp->ifa_name);
      //  create a packet socket at index
      //  AF_PACKET makes it a packet socket
      //  SOCK_RAW makes it so we get the entire packet
      //  could also use SOCK_DGRAM to cut off link layer header
      //  ETH_P_ALL indicates we want all (upper layer) protocols
      //  we could specify just a specific one
      packet_socket[index] = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
      if (packet_socket[index] < 0)
      {
        perror("socket");
        return 2;
      }
      // Place to store MAC address
      s = (struct sockaddr_ll *)(tmp->ifa_addr);
      int i;
      int len = 0;
      // Change MAC to a string
      for (i = 0; i < 6; i++)
      {
        len += sprintf(macp + len, "%02X%s", s->sll_addr[i], i < 5 ? ":" : "");
      }
      printf("Interface name : %s\n Interface Address : %s\n", (ifaddr)->ifa_name, macp);
      printf("Mac: %s\n", macp);
      // Copy MAC to buffer and increase counter
      memcpy(&routerAddress[counter], macp, sizeof(macp));
      counter += 46;

      // Copy IP to buffer and increase counter
      char *ip;
      ifr.ifr_ifru.ifru_addr.sa_family = AF_INET;
      strncpy(ifr.ifr_name, tmp->ifa_name, IFNAMSIZ - 1);
      ioctl(packet_socket[index], SIOCGIFADDR, &ifr);
      ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_ifru.ifru_addr)->sin_addr);
      printf("Ip: %s\n", ip);
      ipAddress[ipCounter] = *ip;
      ipCounter+= 8;
      memcpy(&routerAddress[counter], ip, sizeof(ip));
      counter += 8;

      // Bind the socket to the address, so we only get packets
      // recieved on this specific interface. For packet sockets, the
      // address structure is a struct sockaddr_ll (see the man page
      // for "packet"), but of course bind takes a struct sockaddr.
      // Here, we can use the sockaddr we got from getifaddrs (which
      // we could convert to sockaddr_ll if we needed to)
      if (bind(packet_socket[index], tmp->ifa_addr, sizeof(struct sockaddr_ll)) == -1)
      {
        perror("bind");
        exit(8);
      }
      // Set socket in file descriptor
      FD_SET(packet_socket[index], &myfds);
      FD_SET(STDIN_FILENO, &myfds);
      setsockopt(packet_socket[index], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

      // Prepare for the next socket
      index++;

      if (!strncmp(&(tmp->ifa_name[3]), "eth1", 4))
      {
        memcpy(device_name, tmp->ifa_name, 2);
        printf("Interface name : %s\n", device_name);
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
    // Place to hold packet we receive
    char buf[1500];
    // Temp file descriptor
    fd_set fdstmp = myfds;
    // Wait for an actual message
    int nn = select(FD_SETSIZE, &fdstmp, NULL, NULL, NULL);
    // Struct to receive message
    struct sockaddr_ll recvaddr;
    // Length of received message
    unsigned int recvaddrlen = sizeof(struct sockaddr_ll);

    for (int j = 0; j < 10; ++j)
    {
      // If there is a packet in this socket
      if (FD_ISSET(packet_socket[j], &fdstmp))
      {
        // we can use recv, since the addresses are in the packet, but we
        // use recvfrom because it gives us an easy way to determine if
        // this packet is incoming or outgoing (when using ETH_P_ALL, we
        // see packets in both directions. Only outgoing can be seen when
        // using a packet socket with some specific protocol)
        int n = recvfrom(packet_socket[j], buf, 1500, 0, (struct sockaddr *)&recvaddr, &recvaddrlen);
        // Temporary buffer to hold packet info
        char temp_buf[n];
        // TODO 3:  Find an entry in
        // the routing table, with prefix matching dest IP addr in
        // the packet.  I read this as, if this isn't us, then we need to
        // forward.  So, we need to look it up.  Maybe have a bool to keep
        // track of whether or not the ip is "us"

        // TODO 4: if no such entry exists, send back an ICMP destination
        // unreachable (network unreachable) message.  So, bools if false
        // send ICMP

        // ignore outgoing packets (we can't disable some from being sent
        // by the OS automatically, for example ICMP port unreachable
        // messages, so we will just ignore them here)
        if (recvaddr.sll_pkttype == PACKET_OUTGOING)
          continue;
        // start processing all others
        eh.ether_type = ntohs(0x0000);
        memcpy(&eh, buf, 14);

        // Sequence num is the ttl -- 32 hops and done.  Decrement if we hit 0, drop packet, and send ICMP time exceeded message.
        // TODO 2: We think this is done if we are assuming that checksum and ttl
        // are checked once we decide the packet is for us??
        // Decrement TTL or sequence num
        // If zero, due to this operation, send back a ICMP time exceeded (TTL exceed)
        // message and drop the original packet.  Otherwise, you must recompute
        // the IP checksum due to the changed TTL.

        // Verify Checksum from sender, consider wrapping send function and resetting some info

        // When the packet is an ICMP or IPv4
        if (ntohs(eh.ether_type) == 0x0800)
        {
          memcpy(&iph, &buf[14], sizeof(iph));
          memcpy(&iphResponse, &iph, sizeof(iph));

          // Forward packet
          if (iph.protocol != 1)
          {
            uint16_t temp_checksum = iph.check;
            iph.check = 0;
            memcpy(&buf[14], &iph, sizeof(iph));
            iph.check = checksum(&buf[14], sizeof(iph));
            printf("OG checksum %u\n", ntohs(temp_checksum));
            printf("Our checksum %u\n", ntohs(iph.check));
            printf("Tot len %u\n", ntohs(iph.tot_len));
            iph.ttl--;

            // Reenter while if bad checksum
            if (ntohs(iph.check) != ntohs(temp_checksum))
              continue;
            // Send Time Exceeded Message
            else if (iph.ttl == 0)
            {
              printf("Packet Timeout\n\n");
              // build IP portion
              memcpy(&iphResponse.saddr, &iph.daddr, sizeof(iph.daddr)); /*change to be our IP address*/
              memcpy(&iphResponse.daddr, &iph.saddr, sizeof(iph.saddr));
              // build EH portion
              memcpy(ehResponse.ether_dhost, eh.ether_shost, sizeof(eh.ether_shost));
              memcpy(ehResponse.ether_shost, eh.ether_dhost, sizeof(eh.ether_dhost)); /*change to be our MAC address*/
              memcpy(&ehResponse.ether_type, &eh.ether_type, sizeof(eh.ether_type));

              // Set type and checksum to zero
              icmp.type = 11;
              icmp.checksum = 0;
              icmp.code = 0;
              icmp.seqnum = 1;
              icmp.id = 0;

              iphResponse.ttl = 32;
              // Add everything to the message to send
              memcpy(&temp_buf, &ehResponse, sizeof(ehResponse));
              memcpy(&temp_buf[14], &iphResponse, sizeof(iphResponse));
              memcpy(&temp_buf[34], &icmp, sizeof(icmp));
              // Data
              memcpy(&temp_buf[42], &buf[42], n - 42);

              // Calculate checksum
              icmp.checksum = checksum(&temp_buf[14], n - 14);
              memcpy(&temp_buf[36], &icmp.checksum, 2);
              // Send ICMP Echo Reply
              int success = send(packet_socket[j], temp_buf, n, 0);
              if (success == -1)
              {
                perror("send():");
                exit(90);
              }
              continue;
            }

            /********************* Forward pack here ***********************/
            char *fileName = "-table.txt";
            if(strstr("r1", device_name)){
              strcpy(device_name, "r1");
            }
            else{
              strcpy(device_name, "r2");
            }
            strcat(&device_name[2], fileName);
            printf("file name: %s\n", device_name);
            FILE *file;
            file = fopen(device_name, "r+");
            printf("file open\n");
            // if the file is Null return the error message, exit, and notify the client
            if (file == NULL)
            {
              printf("Error! Could not open file\n");
              exit(-1);
            }
            int fileCounter = 0;
            do
            {
              fgets(&routingTable[fileCounter], 23, file);
              fileCounter += 23;
            } while (!feof(file));

            printf("file contents 1\n%s\n", routingTable);
            printf("file contents 2\n%s\n", &routingTable[23]);
            printf("file contents 3\n%s\n", &routingTable[46]);
            printf("file contents 4\n%s\n", &routingTable[69]);
            printf("file contents 5\n%s\n", &routingTable[92]);

            int desiredSocket = -1;
            for (int i = 0; i < 130; i += 23)
            {
              char temp_ip[INET_ADDRSTRLEN];
              char temp_tip[INET_ADDRSTRLEN];
              strncpy(temp_ip, &routingTable[i + 23], 8);
              inet_ntop(AF_INET, &(iph.daddr), temp_tip, INET_ADDRSTRLEN);
              strcpy(&temp_tip[7], "0");
              strcpy(&temp_ip[7], "0");
              printf("temp tip : %s\n", temp_tip);
              printf("temp ip : %s\n", temp_ip);
              
              
              
              if (!strcmp(temp_ip, temp_tip))
              {
                printf("match found");
                desiredSocket = i;
                printf("socket assigned");
                break;
              }
            }
            if (desiredSocket == -1)
            {
              // Create ICMP Destination Unreachable
              printf("Network Unreachable packet\n\n");

              // build IP portion
              memcpy(&iphResponse.saddr, &iph.daddr, sizeof(iph.daddr)); /*change to be our IP address*/
              memcpy(&iphResponse.daddr, &iph.saddr, sizeof(iph.saddr));
              // build EH portion
              memcpy(ehResponse.ether_dhost, eh.ether_shost, sizeof(eh.ether_shost));
              memcpy(ehResponse.ether_shost, eh.ether_dhost, sizeof(eh.ether_dhost)); /*change to be our MAC address*/
              memcpy(&ehResponse.ether_type, &eh.ether_type, sizeof(eh.ether_type));

              // Set type and checksum to zero
              icmp.type = 3;
              icmp.checksum = 0;
              icmp.code = 0;
              icmp.seqnum = 1;
              icmp.id = 0;

              iphResponse.ttl = 32;
              // Add everything to the message to send
              memcpy(&temp_buf, &ehResponse, sizeof(ehResponse));
              memcpy(&temp_buf[14], &iphResponse, sizeof(iphResponse));
              memcpy(&temp_buf[34], &icmp, sizeof(icmp));
              // Data
              memcpy(&temp_buf[42], &buf[42], n - 42);

              // Calculate checksum
              icmp.checksum = checksum(&temp_buf[14], n - 14);
              memcpy(&temp_buf[36], &icmp.checksum, 2);
              // Send ICMP Echo Reply
              int success = send(packet_socket[j], temp_buf, n, 0);
              if (success == -1)
              {
                perror("send():");
                exit(90);
              }
              continue;
            }
            printf("buffer cached");
            // Set Source IP and build an ARP Response
            char buffCache[1500];
            memcpy(&buffCache, buf, sizeof(buf));
            char temp_tip[INET_ADDRSTRLEN];
            strncpy(temp_tip, &routerAddress[(desiredSocket * 54) + 46], 8);
            inet_ntop(AF_INET, &(arpRequest.arp_spa), temp_tip, INET_ADDRSTRLEN);

            // Broadcast value
            char *broadcast = "255.255.255.255";

            // Put broadcast and our mac Addr in the ArpRequest
            memcpy(arpRequest.arp_tha, ether_aton(broadcast), 6);
            memcpy(arpRequest.arp_sha, ether_aton(temp_mac), 6);

            // Set Destination IP
            memcpy(&temp_tip, "10.0.0.2", 8);
            inet_ntop(AF_INET, &(arpRequest.arp_spa), temp_tip, INET_ADDRSTRLEN);

            // Set up the rest of the ea_hdr
            arpRequest.ea_hdr.ar_pln = 4;
            arpRequest.ea_hdr.ar_op = htons(1);
            arpRequest.ea_hdr.ar_hln = 6;
            arpRequest.ea_hdr.ar_hrd = htons(1);
            arpRequest.ea_hdr.ar_pro = 8;

            // Ether header
            memcpy(ehRequest.ether_shost, ether_aton(temp_mac), 6);
            memcpy(ehRequest.ether_dhost, ether_aton(broadcast), 6);
            ehRequest.ether_type = htons(0x0806);

            memcpy(&temp_buf[0], &ehRequest, 14);
            memcpy(&temp_buf[14], &arpRequest, sizeof(arpRequest));

            int success = send(packet_socket[j], temp_buf, n, 0);
            if (success == -1)
            {
              perror("send():");
              exit(90);
            }
            // found the network to send an ARP Request
            int f = recvfrom(packet_socket[j], buf, 1500, 0, (struct sockaddr *)&recvaddr, &recvaddrlen);

            if (f != -1)
            {
              // Copy ether header
              memcpy(&eh, buf, 14);
              if (ntohs(eh.ether_type) == 0x0806)
              {
                // check that the arp header no longer holds the broadcast value
                memcpy(&ehResponse.ether_shost, eh.ether_dhost, sizeof(eh.ether_dhost));
                memcpy(&ehResponse.ether_dhost, eh.ether_shost, sizeof(eh.ether_shost));
                ehResponse.ether_type = htons(0x0800);

                memcpy(&buffCache[0], &ehResponse, 14);
                int forwarded = send(packet_socket[j], temp_buf, n, 0);
                if (forwarded == -1)
                {
                  perror("send():");
                  exit(90);
                }
                printf("Forwarded: %d\n", forwarded);
              }
            }
            else
            {
              // Send ICMP
              // Create ICMP Destination Unreachable
              printf("Host Unreachable packet\n\n");

              // build IP portion
              memcpy(&iphResponse.saddr, &iph.daddr, sizeof(iph.daddr)); /*change to be our IP address*/
              memcpy(&iphResponse.daddr, &iph.saddr, sizeof(iph.saddr));
              // build EH portion
              memcpy(ehResponse.ether_dhost, eh.ether_shost, sizeof(eh.ether_shost));
              memcpy(ehResponse.ether_shost, eh.ether_dhost, sizeof(eh.ether_dhost)); /*change to be our MAC address*/
              memcpy(&ehResponse.ether_type, &eh.ether_type, sizeof(eh.ether_type));

              // Set type and checksum to zero
              icmp.type = 3;
              icmp.checksum = 0;
              icmp.code = 1;
              icmp.seqnum = 1;
              icmp.id = 0;

              iphResponse.ttl = 32;
              // Add everything to the message to send
              memcpy(&temp_buf, &ehResponse, sizeof(ehResponse));
              memcpy(&temp_buf[14], &iphResponse, sizeof(iphResponse));
              memcpy(&temp_buf[34], &icmp, sizeof(icmp));
              // Data
              memcpy(&temp_buf[42], &buf[42], n - 42);

              // Calculate checksum
              icmp.checksum = checksum(&temp_buf[14], n - 14);
              memcpy(&temp_buf[36], &icmp.checksum, 2);
              // Send ICMP Echo Reply
              int unreachable = send(packet_socket[j], temp_buf, n, 0);
              if (unreachable == -1)
              {
                perror("send():");
                exit(90);
              }
              continue;
            }
          }
          // reply to ICMP
          else
          {
            printf("ICMP\n\n");

            // build IP portion
            memcpy(&iphResponse.saddr, &iph.daddr, sizeof(iph.daddr));
            memcpy(&iphResponse.daddr, &iph.saddr, sizeof(iph.saddr));
            // build EH portion
            memcpy(ehResponse.ether_dhost, eh.ether_shost, sizeof(eh.ether_shost));
            memcpy(ehResponse.ether_shost, eh.ether_dhost, sizeof(eh.ether_dhost));
            memcpy(&ehResponse.ether_type, &eh.ether_type, sizeof(eh.ether_type));
            // Store all of the ICMP info
            memcpy(&icmp, &buf[34], sizeof(icmp));

            // Set type and checksum to zero
            icmp.type = ntohs(0x0000);
            icmp.checksum = 0;

            // Add everything to the message to send
            memcpy(&temp_buf, &ehResponse, sizeof(ehResponse));
            memcpy(&temp_buf[14], &iphResponse, sizeof(iphResponse));
            memcpy(&temp_buf[34], &icmp, sizeof(icmp));
            // Data
            memcpy(&temp_buf[42], &buf[42], n - 42);

            // Calculate checksum
            icmp.checksum = checksum(&temp_buf[14], n - 14);
            memcpy(&temp_buf[36], &icmp.checksum, 2);
            // Send ICMP Echo Reply
            int success = send(packet_socket[j], temp_buf, n, 0);
            if (success == -1)
            {
              perror("send():");
              exit(90);
            }
          }
        }
        // when an ARP request is processed, respond
        else if (ntohs(eh.ether_type) == 0x0806)
        {
          // TODO 5: USING route table entry found, determine the interface
          // and next hop IP address.  Next hop only used in ARP, we do not
          // put this address into the packet being forwarded in any way.

          // TODO 5 continued: construct an ARP request, to find the ethernet
          // address corresponding to the next hop IP address.  Send this request
          // out on the correct interface from the previous step, and receive the
          // reply.  You may use a cache to bypass this step, although you are not
          // required to.  If there is no ARP response, send back and ICMP destination
          // unreachable (host unreachable) message.  Maybe consider extracting ICMP
          // logic to function so we can call it down here.  Print out next hop IP and
          // mac addresses we obtain from the routing table and from ARP.

          // TODO 5 again: while loop where we wait to receive ARP reply from IP
          // and if no response, send ICMP.  Also, store old packet.  If reply succesful
          // update ether header dhost (see TODO 6).

          // TODO 6: Using the ethernet address found through arp as the destination
          // and the ethernet address of the interface you are sending on as the source,
          // construct a new ethernet header for the packet being forwarded

          // TODO 7: Send out the packet on the appropriate interface (packet_socket)

          // Print statements to verify what we are receiving
          printf("Packet socket in ARP Request: %d\n\n", packet_socket[j]);
          printf("Received Ether Destination: %s\n", ether_ntoa((struct ether_addr *)&eh.ether_dhost));
          printf("Received Ether Source: %s\n", ether_ntoa((struct ether_addr *)&eh.ether_shost));
          printf("Received Ether Type: %s\n", ether_ntoa((struct ether_addr *)&eh.ether_type));

          memcpy(&arpReceived, &buf[14], sizeof(arpReceived));

          // Find the right MAC address associated with IP
          for (int i = 0; i < sizeof(routerAddress); i += 54)
          {
            char temp_ip[9];
            char temp_tip[INET_ADDRSTRLEN];
            strncpy(temp_ip, &routerAddress[i + 46], 8);
            inet_ntop(AF_INET, &(arpReceived.arp_tpa), temp_tip, INET_ADDRSTRLEN);
            if (!strcmp(temp_ip, temp_tip))
            {
              memcpy(&temp_mac, &routerAddress[i], 46);
              break;
            }
          }
          printf("Mac in ARP: %s\n", temp_mac);
          // Set ARP response to received and change op code to 2
          arpResponse = arpReceived;
          arpResponse.ea_hdr.ar_op = htons(2);

          // create ARP packet to the request with previous information and host MAC address
          memcpy(arpResponse.arp_tha, arpReceived.arp_sha, sizeof(arpReceived.arp_sha));
          memcpy(arpResponse.arp_tpa, arpReceived.arp_spa, sizeof(arpReceived.arp_spa));
          memcpy(arpResponse.arp_spa, arpReceived.arp_tpa, sizeof(arpReceived.arp_tpa));
          memcpy(arpResponse.arp_sha, ether_aton(temp_mac), 6);

          // Set up ether header
          memcpy(ehResponse.ether_dhost, eh.ether_shost, sizeof(eh.ether_shost));
          memcpy(ehResponse.ether_shost, arpResponse.arp_sha, 6);
          memcpy(&ehResponse.ether_type, &eh.ether_type, sizeof(eh.ether_type));
          // Store everything in the buffer
          memcpy(&temp_buf[0], &ehResponse, sizeof(ehResponse));
          memcpy(&temp_buf[14], &arpResponse, sizeof(arpResponse));
          // Print statements to verify ether header info
          printf("Response Ether Destination: %s\n", ether_ntoa((struct ether_addr *)&ehResponse.ether_dhost));
          printf("Response Ether Source: %s\n", ether_ntoa((struct ether_addr *)&ehResponse.ether_shost));
          printf("Response Ether Type: %s\n\n", ether_ntoa((struct ether_addr *)&ehResponse.ether_type));
          // Send ARP Reply
          int success = send(packet_socket[j], temp_buf, n, 0);
          if (success == -1)
          {
            perror("send():");
            exit(90);
          }

          // Reset all of the info for type
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
