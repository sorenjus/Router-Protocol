
struct ether_arp arpReceived, arpResponse, arpRequest;
struct ether_header eh, ehRequest, ehResponse;

//Set Source IP
char temp_tip[INET_ADDRSTRLEN];
strncpy(temp_ip, &routerAddress[i + 46], 8);
inet_ntop(AF_INET, &(arpRequest.arp_spa), temp_tip, INET_ADDRSTRLEN);

//Broadcast value
uint8_t broadcast = 255.255.255.255;

//Put broadcast and our mac Addr in the ArpRequest
memcpy(arpRequest.arp_tha, ether_aton(broadcast), 6);
memcpy(arpRequest.arp_sha, ether_aton(temp_mac), 6);

//Set Destination IP
temp_tip = "10.0.0.2";
inet_ntop(AF_INET, &(arpRequest.arp_spa), temp_tip, INET_ADDRSTRLEN);

/*Set up the rest of the ea_hdr
 *
 *need htons????
 *
 */
arpRequest.ea_hdr.ar_pln = 4;
arpRequest.ea_hdr.ar_op = htons(1);
arpRequest.ea_hdr.ar_hln = 6;
arpRequest.ea_hdr.ar_hrd = htons(1);
arpRequest.ea_hdr.ar_pro = 8;
 
//Ether header
 memcpy(ehRequest.ether_shost, ether_aton(temp_mac), 6);
 memcpy(ehRequest.ether_dhost, ether_aton(broadcast), 6);
 ehRequest.ether_type = ntons(0x0806);

memcpy(&temp_buf[0], ehRequest, 14);
memcpy(&temp_buf[14], arpRequest, sizeof(arpRequest));

int success = send(packet_socket[j], temp_buf, n, 0);
if (success == -1)
{
  perror("send():");
  exit(90);
}

recvfrom(packet_socket[j], buf, 1500, 0, (struct sockaddr *)&recvaddr, &recvaddrlen);

memcpy(&eh, buf, 14);
//process the mac address if it's an Arp Packet
if(ntohs(eh.ether_type) == 0x0806){
    //check that the arp header no longer holds the broadcast value
    //if it does, host unreachable
    //else copy the hardware address into our etherheader of the original packet
}
