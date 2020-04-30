#include "skel.h"

/* Comparator for qsort. */
int comparator(const void *p, const void *q) {
    if (ntohl(((struct route_table_entry *)p)->prefix) == ntohl(((struct route_table_entry *)q)->prefix)) {
        return ntohl(((struct route_table_entry *)p)->mask) - ntohl(((struct route_table_entry *)q)->mask);
    }
    return ntohl(((struct route_table_entry *)p)->prefix) - ntohl(((struct route_table_entry *)q)->prefix);
}

/**
 * Function to search for the entry that matches the given dest_ip & mask while
 * entry's mask has to be equal to parameter mask.
 */
struct route_table_entry *binary_search(struct route_table_entry *rtable, long l, long r, __u32 dest_ip, __u32 mask) {
    if (r >= l) {
        long mid = l + (r - l) / 2;
        if (rtable[mid].prefix == (dest_ip & mask)) {
            if (rtable[mid].mask == mask) {
                return &rtable[mid];
            } 
            /* In rtable we are sorting after prefix and then masks are sorted
             * in ascending order from shortest length to longest. So in rtable
             * when prefix is the same and we consider -inf to be the smallest
             * they will look like this: -inf ... -256 ... -1. Let's say we need
             *                                 ^        ^-------------------<
             *                                 ^-------------<              |
             * to find mask -4 so we check if -4 < -256 then |              |
             * if it's true we look -------------------------^ else we look ^
             */
            else if (ntohl(mask) < ntohl(rtable[mid].mask)) {
                return binary_search(rtable, l, mid - 1, dest_ip, mask);
            }
        }
        if (ntohl(rtable[mid].prefix) > ntohl((dest_ip & mask))) {
            return binary_search(rtable, l, mid - 1, dest_ip, mask);
        }
        return binary_search(rtable, mid + 1, r, dest_ip, mask);
    }
    return NULL;
}

/**
 * We search after the longest mask towards the shortest mask and return
 * NULL if we can't find a match.  
 */
struct route_table_entry *get_best_route(struct route_table_entry *rtable, long l, long r, __u32 dest_ip) {

    struct route_table_entry *best_match = NULL;

    __u32 mask = -1;
    while (mask != 0) {
        best_match = binary_search(rtable, l, r, dest_ip, htonl(mask));
        if (best_match != NULL) {
            printf("%d\n", ntohl(best_match->mask));
            return best_match;
        }
        mask = mask << 1;
    }
    
    return NULL;
}

/**
 * Returns mac of parameter ip if found in arp_table, else NULL.
 */
struct arp_entry *get_arp_entry(struct arp_entry  *arp_table, long arp_table_len, __u32 ip) {
    for (int i = 0; i < arp_table_len; i++) {
        if (arp_table[i].ip == ip) {
            return &arp_table[i];
        }
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    
    packet m;
    packet *tmp_m;
	int rc;

	init();
    
    struct route_table_entry *rtable = NULL;
    long rtable_size = read_rtable(&rtable);
    qsort((void*)rtable, rtable_size, sizeof(rtable[0]), comparator);

    struct queue *q = queue_create();
    long q_size = 0;
    struct arp_entry *arp_table = NULL;
    long arp_table_size = 0;

    uint8_t mac_buff[20];
    uint16_t ip_hdr_checkSum;
    char *interface_to_ip_tmp;
    u_char *interface_ip;
    u_char drop_packet;
    struct in_addr ip_holder;

	while (1) {
        drop_packet = 0;
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		struct ether_header *eth_hdr = (struct ether_header*) m.payload;
        if (eth_hdr->ether_type == htons(ETHERTYPE_ARP)) {

            struct ether_arp *eth_arp = (struct ether_arp*) (m.payload + sizeof(struct ether_header));

            if (eth_arp->arp_op == htons(ARPOP_REQUEST)) {
                // host (h0) sends ARP_REQUEST implementation. Router must reply with MAC of interface from packet.
                interface_to_ip_tmp = get_interface_ip(m.interface);
                interface_ip = convert_ip(interface_to_ip_tmp);
                
                for (int i = 0; i < PACOUNT; i++) {
                    if (interface_ip[i] != eth_arp->arp_tpa[i]) {
                        drop_packet = 1;
                        break;
                    }
                }
                free(interface_ip); // was dinamically allocated returned from function. 
                if (drop_packet) {
                    // Packet was not meant to be for me.
                    continue;
                }

                get_interface_mac(m.interface, mac_buff);

                eth_arp->arp_hrd = htons(ARPHRD_ETHER);
                eth_arp->arp_pro = htons(ETHERTYPE_IP);
                eth_arp->arp_hln = MACPIECES;
                eth_arp->arp_pln = PACOUNT;
                eth_arp->arp_op = htons(ARPOP_REPLY);

                for (int i = 0; i < MACPIECES; i++) {
                    eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];
                    eth_arp->arp_tha[i] = eth_arp->arp_sha[i];
                    eth_hdr->ether_shost[i] = mac_buff[i];
                    eth_arp->arp_sha[i] = mac_buff[i];
                }

                for (int i = 0; i < PACOUNT; i++) {
                    uint8_t tmp = eth_arp->arp_spa[i];
                    eth_arp->arp_spa[i] = eth_arp->arp_tpa[i];
                    eth_arp->arp_tpa[i] = tmp;
                }

                send_packet(m.interface, &m);
            }
            else if (eth_arp->arp_op == htons(ARPOP_REPLY)) {
                // host (h0) ARP_REPLY implementation. Add to struct arp_entry *arp_table.

                update_arp_table(&arp_table, &arp_table_size, eth_hdr->ether_shost, eth_arp->arp_spa);
                if (!queue_empty(q)) {
                    // Search for packet whose arp reply was for.
                    for (int i = 0; i < q_size; i++) {
                        tmp_m = queue_deq(q);

		                struct iphdr *tmp_ip_hdr = (struct iphdr*)(tmp_m->payload + IP_OFF);

                        char buff[20];
                        sprintf(buff, "%d.%d.%d.%d", eth_arp->arp_spa[0], eth_arp->arp_spa[1], eth_arp->arp_spa[2], eth_arp->arp_spa[3]);
                        inet_aton(buff, &ip_holder);
                        
                        if (tmp_ip_hdr->daddr == ip_holder.s_addr) {
                            // Found packet. Let's prepare it for sending.                            
                            break;
                        }
                        queue_enq(q, tmp_m);
                    }

            		struct ether_header *tmp_eth_hdr = (struct ether_header*) tmp_m->payload;
		            struct iphdr *tmp_ip_hdr = (struct iphdr*)(tmp_m->payload + IP_OFF);
                    struct route_table_entry *best_route = get_best_route(rtable, 0, rtable_size - 1, tmp_ip_hdr->daddr);

                    ip_holder.s_addr = tmp_ip_hdr->daddr;

                    for (int i = 0; i < MACPIECES; i++) {
                        uint8_t tmp = tmp_eth_hdr->ether_dhost[i];
                        tmp_eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];
                        tmp_eth_hdr->ether_shost[i] = tmp;
                    }

                    send_packet(best_route->interface, tmp_m); 
                }
            }
        }
        else if (eth_hdr->ether_type == htons(ETHERTYPE_IP)) {

		    struct iphdr *ip_hdr = (struct iphdr*)(m.payload + IP_OFF);

            inet_aton(get_interface_ip(m.interface), &ip_holder);
            if (ip_hdr->daddr == ip_holder.s_addr) {
                if (ip_hdr->protocol == PROTOCOLICMPVALUE) {
                    struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + ICMP_OFF);
                    if (icmp_hdr->type == ICMP_ECHO) {
                        // Send back a icmp echo reply packet.
                        ip_hdr->ttl = 64;
                        ip_hdr->protocol = PROTOCOLICMPVALUE;
                        __u32 tmp = ip_hdr->saddr;
                        ip_hdr->saddr = ip_hdr->daddr;
                        ip_hdr->daddr = tmp;
                        ip_hdr->check = 0;
                        ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));
                        
                        eth_hdr->ether_type = htons(ETHERTYPE_IP);
                        
                        icmp_hdr->type = ICMP_ECHOREPLY;
                        icmp_hdr->code = 0;
                        icmp_hdr->checksum = 0;
                        icmp_hdr->checksum = checksum(icmp_hdr, sizeof(struct icmphdr));

                        struct route_table_entry *best_route = get_best_route(rtable, 0, rtable_size - 1, ip_hdr->saddr);
                        if (best_route == NULL) {
                            // Just in case. This "if" should never be accesed though.
                            continue;
                        }
                        for (int i = 0; i < MACPIECES; i++) {
                            uint8_t tmp2 = eth_hdr->ether_shost[i];
                            eth_hdr->ether_shost[i] = eth_hdr->ether_dhost[i];
                            eth_hdr->ether_dhost[i] = tmp2;
                        }
                        send_packet(m.interface, &m);
                    }
                }
                continue;
            }

            /* Check TTL <= 1 */
            if (ip_hdr->ttl <= 1) {
                // Send back a icmp echo reply packet.
                m.len = ICMP_OFF + sizeof(struct icmphdr);

                ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
                ip_hdr->ttl = 64;
                ip_hdr->protocol = PROTOCOLICMPVALUE;
                __u32 tmp = ip_hdr->saddr;
                ip_hdr->saddr = ip_hdr->daddr;
                ip_hdr->daddr = tmp;
                ip_hdr->check = 0;
                ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));

                struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + ICMP_OFF);
                icmp_hdr->type = ICMP_TIME_EXCEEDED;
                icmp_hdr->code = 0;
                icmp_hdr->checksum = 0;
                icmp_hdr->checksum = checksum(icmp_hdr, sizeof(struct icmphdr));

                struct route_table_entry *best_route = get_best_route(rtable, 0, rtable_size - 1, ip_hdr->daddr);
                m.interface = best_route->interface;
                if (best_route == NULL) {
                    // Just in case. This "if" should never be accesed though.
                    continue;
                }
                for (int i = 0; i < MACPIECES; i++) {
                    uint8_t tmp = eth_hdr->ether_shost[i];
                    eth_hdr->ether_shost[i] = eth_hdr->ether_dhost[i];
                    eth_hdr->ether_dhost[i] = tmp;
                }

                send_packet(m.interface, &m);
                continue;
            }

            ip_hdr_checkSum = ip_hdr->check;
            ip_hdr->check = 0;
                
            if (ip_hdr_checkSum != checksum(ip_hdr, sizeof(struct iphdr))) {
                continue;
            }

            ip_hdr->ttl--;
            ip_hdr->check = 0;
            ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));

            struct route_table_entry *best_route = get_best_route(rtable, 0, rtable_size - 1, ip_hdr->daddr);
            if (best_route == NULL) {
                // Send back a icmp echo reply packet.
                m.len = ICMP_OFF + sizeof(struct icmphdr);

                ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
                ip_hdr->ttl = 64;
                ip_hdr->protocol = PROTOCOLICMPVALUE;
                __u32 tmp = ip_hdr->saddr;
                ip_hdr->saddr = ip_hdr->daddr;
                ip_hdr->daddr = tmp;
                ip_hdr->check = 0;
                ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));

                struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + ICMP_OFF);
                icmp_hdr->type = ICMP_DEST_UNREACH;
                icmp_hdr->code = 0;
                icmp_hdr->checksum = 0;
                icmp_hdr->checksum = checksum(icmp_hdr, sizeof(struct icmphdr));

                struct route_table_entry *best_route = get_best_route(rtable, 0, rtable_size - 1, ip_hdr->daddr);
                m.interface = best_route->interface;
                if (best_route == NULL) {
                    // Just in case. This "if" should never be accesed though.
                    continue;
                }
                for (int i = 0; i < MACPIECES; i++) {
                    uint8_t tmp = eth_hdr->ether_shost[i];
                    eth_hdr->ether_shost[i] = eth_hdr->ether_dhost[i];
                    eth_hdr->ether_dhost[i] = tmp;
                }

                send_packet(m.interface, &m);
                continue;
            }
                
            ip_holder.s_addr = best_route->next_hop;
            struct arp_entry *arp_e = get_arp_entry(arp_table, arp_table_size, best_route->next_hop);

            if (arp_e == NULL) {
                // Add packet to a queue.

                ip_holder.s_addr = ip_hdr->daddr;
                ip_holder.s_addr = ip_hdr->saddr;

                q_size++;
                tmp_m = (packet*) malloc(sizeof(packet));
                memcpy(tmp_m, &m, sizeof(m));
                queue_enq(q, tmp_m);

                // Send a new ARP_REQUEST packet on destination interface.

                m.interface = best_route->interface;
                m.len = sizeof(struct ether_header) + sizeof(struct ether_arp);
                
                eth_hdr->ether_type = htons(ETHERTYPE_ARP);

                struct ether_arp *eth_arp = (struct ether_arp*) (m.payload + sizeof(struct ether_header));

                eth_arp->arp_hrd = htons(ARPHRD_ETHER);
                eth_arp->arp_pro = htons(ETHERTYPE_IP);
                eth_arp->arp_hln = MACPIECES;
                eth_arp->arp_pln = PACOUNT;
                eth_arp->arp_op = htons(ARPOP_REQUEST);

                ip_holder.s_addr = ip_hdr->saddr;
                char *tmp_buff = inet_ntoa(ip_holder);
                u_char *ip_tmp_req_format = convert_ip(tmp_buff);
                for (int i = 0; i < PACOUNT; i++) {
                    eth_arp->arp_spa[i] = ip_tmp_req_format[i];
                }
                free(ip_tmp_req_format);

                ip_holder.s_addr = best_route->next_hop;
                tmp_buff = inet_ntoa(ip_holder);
                ip_tmp_req_format = convert_ip(tmp_buff);
                for (int i = 0; i < PACOUNT; i++) {
                    eth_arp->arp_tpa[i] = ip_tmp_req_format[i];
                }
                free(ip_tmp_req_format);

                get_interface_mac(m.interface, eth_hdr->ether_shost);
                get_interface_mac(m.interface, eth_arp->arp_sha);
                for (int i = 0; i < MACPIECES; i++) {
                    eth_hdr->ether_dhost[i] = 255;
                    eth_arp->arp_tha[i] = 255;
                }

                send_packet(m.interface, &m);
                continue;
            }

            get_interface_mac(m.interface, eth_hdr->ether_shost);
            for (int i = 0; i < MACPIECES; i++) {
                eth_hdr->ether_dhost[i] = arp_e->mac[i];
            }
            send_packet(best_route->interface, &m);
        }
	}
}
