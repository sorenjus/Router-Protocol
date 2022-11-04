
struct ether_arp arpReceived, arpResponse, arpRequest;
struct ether_header ehRequest, ehResponse;

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
 *
 *
 */
 
 memcpy(ehRequest.ether_shost, ether_aton(temp_mac), 6);
 memcpy(ehRequest.ether_dhost, ether_aton(broadcast), 6);
 ehRequest.ether_type = ntons(0x0806);
