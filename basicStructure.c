//Read Ether Header
memcpy(&eh, buf, 14);
if (ntohs(eh.ether_type) == 0x0806){
//check if ARP -- check arp_tpa for us
memcpy(&arpReceived, &buf[14], sizeof(arpReceived));
if(arpReceived.arp_tha == &routerAddress[(j * 54) + 46]){ //this should be the IP addr of this interface
    /***************reply to arp packet*********/
}
//if not, foward
else{
/**********forward code*************/
}
}
//if not read IP header
else{
    memcpy(&iph, &buf[14], sizeof(iph));
    //check if this is for us
    if(iph.daddr == &routerAddress[(j * 54) + 46])){ //this should be the IP addr of this interface
    //if ICMP, respond
    }
    else{
        /**************forward code*****************/
    }
}
//else read IP header-- check if for us
//if not forward
