// Read Ether Header
memcpy(&eh, buf, 14);
if (ntohs(eh.ether_type) == 0x0806)
{
    // check if ARP -- check arp_tpa for us
    memcpy(&arpReceived, &buf[14], sizeof(arpReceived));
    if (arpReceived.arp_tha == &routerAddress[(j * 54) + 46])
    { // this should be the IP addr of this interface
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
    // if not, foward
    else
    {
        /**********forward code modified to not have ip header and sends with arpReceived spa instead of ours*************/
    }
}
// if not read IP header
else
{
    memcpy(&iph, &buf[14], sizeof(iph));
    // check if this is for us
    if (iph.daddr == &routerAddress[(j * 54) + 46]))
        { // this should be the IP addr of this interface
            // if ICMP, respond
            if (iph.protocol == 1)
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
            else
            {
                // packet is for us, not ICMP so ignore
            }
        }
    else
    {
        if (iph.ttl == 1)
        {
            printf("TTL Exceeded\n\n");
            // Create ICMP Destination Unreachable
            iphResponse = iph;

            // Build IP Header
            memcpy(&arp_tip, &routerAddress[(j * 54) + 46], 8);
            strncpy(arp_tip, toip(arp_tip), 8);
            x.saddr = inet_addr(arp_tip);
            memcpy(&iphResponse.saddr, &x.saddr, sizeof(iph.daddr));
            memcpy(&iphResponse.daddr, &iph.saddr, sizeof(iph.saddr));
            iphResponse.protocol = 1;
            iphResponse.ttl = 32;
            iphResponse.tot_len = htons(28);
            iphResponse.check = 0;
            memcpy(&buf[14], &iphResponse, sizeof(iph));
            iphResponse.check = checksum(&buf[14], sizeof(iph));

            // build EH portion
            memcpy(ehResponse.ether_dhost, eh.ether_shost, sizeof(eh.ether_shost));
            memcpy(ehResponse.ether_shost, eh.ether_dhost, sizeof(eh.ether_dhost));
            ehResponse.ether_type = htons(0x0800);

            // Setup ICMP properties
            icmp.type = 11;
            icmp.checksum = 0;
            icmp.code = 0;
            icmp.seqnum = 0;
            icmp.id = 0;

            // Add everything to the message to send
            memcpy(&temp_buf, &ehResponse, sizeof(ehResponse));
            memcpy(&temp_buf[14], &iphResponse, sizeof(iphResponse));
            memcpy(&temp_buf[34], &icmp, sizeof(icmp));

            // Calculate checksum
            icmp.checksum = checksum(&temp_buf[14], 28);
            memcpy(&temp_buf[34], &icmp, sizeof(icmp));

            // Original IP header
            memcpy(&temp_buf[42], &iph, sizeof(iph));
            // first 8 bytes of original data
            memcpy(&temp_buf[62], &buf[34], 8);

            // Send ICMP Echo Reply
            int success = send(packet_socket[j], temp_buf, 70, 0);
            if (success == -1)
            {
                perror("send():");
                exit(90);
            }
            continue;
        }
        // Verify checksum
        uint16_t temp_checksum = iph.check;
        iph.check = 0;
        memcpy(&buf[14], &iph, sizeof(iph));
        iph.check = checksum(&buf[14], sizeof(iph));
        iph.ttl--;

        // Reenter while if bad checksum
        if (ntohs(iph.check) != ntohs(temp_checksum))
            continue;

        // Recalculate checksum
        iph.check = 0;
        memcpy(&buf[14], &iph, sizeof(iph));
        iph.check = checksum(&buf[14], sizeof(iph));
        memcpy(&buf[14], &iph, sizeof(iph));

        // Forward Packet Here
        char *fileName = "-table.txt";
        if (strstr(device_name, "r1"))
        {
            strcpy(device_name, "r1");
        }
        else
        {
            strcpy(device_name, "r2");
        }
        strcat(&device_name[2], fileName);
        printf("file name: %s\n", device_name);
        FILE *file;
        file = fopen(device_name, "r+");
        printf("file open\n");

        // if the file is Null return the error message and exit
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

        // printf("file contents 1\n%s\n", routingTable);
        // printf("file contents 2\n%s\n", &routingTable[23]);
        // printf("file contents 3\n%s\n", &routingTable[46]);
        // printf("file contents 4\n%s\n", &routingTable[69]);
        // printf("file contents 5\n%s\n", &routingTable[92]);

        // Iterate through routing table for a matching IP
        int socketCounter = 0;
        bool match, another_router = false;
        do
        {
            char temp_ip[INET_ADDRSTRLEN];
            char temp_tip[INET_ADDRSTRLEN];
            char *nul_char = "\0";
            strncpy(temp_ip, &routingTable[socketCounter], 8);
            inet_ntop(AF_INET, &(iph.daddr), temp_tip, INET_ADDRSTRLEN);
            strcpy(&temp_tip[7], "0");
            strcpy(&temp_ip[7], "0");
            strcat(&temp_tip[8], nul_char);
            strcat(&temp_ip[8], nul_char);

            // Match found
            if (!strncmp(temp_ip, temp_tip, 6))
            {
                char not_another_temp[20];

                // Case where match is another router
                if (strstr(device_name, "r1"))
                {
                    if (!strcmp(temp_ip, "10.3.0.0"))
                    {
                        memcpy(&not_another_temp, "10.0.0.2", 9);
                        strncpy(not_another_temp, toip(not_another_temp), 20);
                        x.daddr = inet_addr(not_another_temp);
                        another_router = true;
                    }
                }
                else if (strstr(device_name, "r2"))
                {
                    if (!strcmp(temp_ip, "10.1.0.0"))
                    {
                        memcpy(&not_another_temp, "10.0.0.1", 9);
                        strncpy(not_another_temp, toip(not_another_temp), 20);
                        x.daddr = inet_addr(not_another_temp);
                        another_router = true;
                    }
                }
                else
                {
                    x.daddr = iph.daddr;
                }
                match = true;
                break;
            }
            socketCounter += 23;
        } while (socketCounter < 130);
        socketCounter = (socketCounter / 23) + 1;

        // Set source MAC address
        if (another_router)
        {
            memcpy(&temp_mac, &routerAddress[54], 46);
        }
        else
        {
            memcpy(&temp_mac, &routerAddress[socketCounter * 54], 46);
        }

        if (!match)
        {
            // Create ICMP Destination Unreachable
            printf("Network Unreachable packet\n\n");

            // Build IP Header
            iphResponse = iph;
            memcpy(&arp_tip, &routerAddress[(j * 54) + 46], 8);
            strncpy(arp_tip, toip(arp_tip), 8);
            x.saddr = inet_addr(arp_tip);
            memcpy(&iphResponse.saddr, &x.saddr, sizeof(iph.daddr));
            memcpy(&iphResponse.daddr, &iph.saddr, sizeof(iph.saddr));
            iphResponse.protocol = 1;
            iphResponse.ttl = 32;
            iphResponse.tot_len = htons(28);
            iphResponse.check = 0;
            memcpy(&buf[14], &iphResponse, sizeof(iph));
            iphResponse.check = checksum(&buf[14], sizeof(iph));

            // build EH portion
            memcpy(ehResponse.ether_dhost, eh.ether_shost, sizeof(eh.ether_shost));
            memcpy(ehResponse.ether_shost, eh.ether_dhost, sizeof(eh.ether_dhost));
            ehResponse.ether_type = htons(0x0800);

            // Setup ICMP properties
            icmp.type = 3;
            icmp.checksum = 0;
            icmp.code = 0;
            icmp.seqnum = 0;
            icmp.id = 0;

            // Add everything to the message to send
            memcpy(&temp_buf, &ehResponse, sizeof(ehResponse));
            memcpy(&temp_buf[14], &iphResponse, sizeof(iphResponse));
            memcpy(&temp_buf[34], &icmp, sizeof(icmp));

            // Calculate checksum
            icmp.checksum = checksum(&temp_buf[14], 28);
            memcpy(&temp_buf[34], &icmp, sizeof(icmp));

            // Original IP header
            memcpy(&temp_buf[42], &iph, sizeof(iph));
            // first 8 bytes of original data
            memcpy(&temp_buf[62], &buf[34], 8);

            // Send ICMP Echo Reply
            int success = send(packet_socket[j], temp_buf, 70, 0);
            if (success == -1)
            {
                perror("send():");
                exit(90);
            }
            continue;
        }
        else
        {
            // Set Source IP and build an ARP Response
            char buffCache[1500];
            memcpy(&buffCache, buf, sizeof(buf));

            // Set MAC depending on the correct interface
            if (another_router)
            {
                memcpy(&arp_tip, &routerAddress[100], 8);
            }
            else
            {
                memcpy(&arp_tip, &routerAddress[(socketCounter * 54) + 46], 8);
            }
            // Setup source IP address
            strncpy(arp_tip, toip(arp_tip), 8);
            x.saddr = inet_addr(arp_tip);

            // Put broadcast and our MAC Addr in the ArpRequest
            memcpy(arpRequest.arp_tha, ether_aton(target_address), 6);
            memcpy(arpRequest.arp_sha, ether_aton(temp_mac), 6);

            // Set Destination IP
            if (another_router)
            {
                memcpy(&arpRequest.arp_tpa, &x.daddr, 8);
            }
            else
            {
                memcpy(&arpRequest.arp_tpa, &iph.daddr, 8);
            }
            memcpy(&arpRequest.arp_spa, &x.saddr, 8);

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

            // Determine if we need to send to a host or another router
            int send_arp;
            if (another_router)
            {
                send_arp = send(packet_socket[1], temp_buf, 42, 0);
                socketCounter = 1;
            }
            else
            {
                send_arp = send(packet_socket[socketCounter], temp_buf, 42, 0);
            }
            if (send_arp == -1)
            {
                perror("send():");
                exit(90);
            }
            // found the network to send an ARP Request
            int f = recvfrom(packet_socket[socketCounter], buf, 1500, 0, (struct sockaddr *)&recvaddr, &recvaddrlen);

            if (f == -1)
            {
                if (errno == EWOULDBLOCK)
                {
                    // Send ICMP
                    // Create ICMP Destination Unreachable
                    printf("Host Unreachable packet\n\n");

                    // Setup IP Header
                    iphResponse = iph;
                    memcpy(&arp_tip, &routerAddress[(j * 54) + 46], 8);
                    strncpy(arp_tip, toip(arp_tip), 8);
                    x.saddr = inet_addr(arp_tip);
                    memcpy(&iphResponse.saddr, &x.saddr, sizeof(iph.daddr));
                    memcpy(&iphResponse.daddr, &iph.saddr, sizeof(iph.saddr));
                    iphResponse.protocol = 1;
                    iphResponse.ttl = 32;
                    iphResponse.tot_len = htons(28);
                    iphResponse.check = 0;
                    memcpy(&buf[14], &iphResponse, sizeof(iph));
                    iphResponse.check = checksum(&buf[14], sizeof(iph));

                    // build EH portion
                    memcpy(ehResponse.ether_dhost, eh.ether_shost, sizeof(eh.ether_shost));
                    memcpy(ehResponse.ether_shost, eh.ether_dhost, sizeof(eh.ether_dhost));
                    ehResponse.ether_type = htons(0x0800);

                    // Setup ICMP properties
                    icmp.type = 3;
                    icmp.checksum = 0;
                    icmp.code = 1;
                    icmp.seqnum = 0;
                    icmp.id = 0;

                    // Add everything to the message to send
                    memcpy(&temp_buf, &ehResponse, sizeof(ehResponse));
                    memcpy(&temp_buf[14], &iphResponse, sizeof(iphResponse));
                    memcpy(&temp_buf[34], &icmp, sizeof(icmp));

                    // Calculate checksum
                    icmp.checksum = checksum(&temp_buf[14], 28);
                    memcpy(&temp_buf[34], &icmp, sizeof(icmp));

                    // Original IP header
                    memcpy(&temp_buf[42], &iph, sizeof(iph));
                    // first 8 bytes of original data
                    memcpy(&temp_buf[62], &buf[34], 8);

                    // Send ICMP Echo Reply
                    int success = send(packet_socket[j], temp_buf, 70, 0);
                    if (success == -1)
                    {
                        perror("send():");
                        exit(90);
                    }
                    continue;
                }
            }
            else
            {
                // Copy ether header
                memcpy(&eh, buf, 14);
                if (ntohs(eh.ether_type) == 0x0806)
                {
                    // check that the arp header no longer holds the broadcast value
                    memcpy(&ehResponse.ether_shost, eh.ether_dhost, sizeof(eh.ether_dhost));
                    memcpy(&ehResponse.ether_dhost, ether_aton(temp_mac), sizeof(eh.ether_shost));
                    ehResponse.ether_type = htons(0x0800);

                    memcpy(&buffCache[0], &ehResponse, 14);
                    int forwarded = send(packet_socket[socketCounter], buffCache, n, 0);
                    if (forwarded == -1)
                    {
                        perror("send():");
                        exit(90);
                    }
                    char temp_tip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(arpRequest.arp_tpa), temp_tip, INET_ADDRSTRLEN);
                    printf("Forwarded a packet to MAC address %s and IP Address %s\n\n",
                           ether_ntoa((struct ether_addr *)&ehResponse.ether_dhost), temp_tip);
                }
            }
        }
    }
}