#include "skel.h"

int interfaces[ROUTER_NUM_INTERFACES];

int get_sock(const char *if_name) {
	int res;
	int s = socket(AF_PACKET, SOCK_RAW, 768);
	DIE(s == -1, "socket");

	struct ifreq intf;
	strcpy(intf.ifr_name, if_name);
	res = ioctl(s, SIOCGIFINDEX, &intf);
	DIE(res, "ioctl SIOCGIFINDEX");

	struct sockaddr_ll addr;
	memset(&addr, 0x00, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = intf.ifr_ifindex;

	res = bind(s , (struct sockaddr *)&addr , sizeof(addr));
	DIE(res == -1, "bind");
	return s;
}

packet* socket_receive_message(int sockfd, packet *m) {
	/* 
	 * Note that "buffer" should be at least the MTU size of the 
	 * interface, eg 1500 bytes 
	 * */
	m->len = read(sockfd, m->payload, MAX_LEN);
	DIE(m->len == -1, "read");
	return m;
}

int send_packet(int sockfd, packet *m) {
	/* 
	 * Note that "buffer" should be at least the MTU size of the 
	 * interface, eg 1500 bytes 
	 * */
	int ret;
	ret = write(interfaces[sockfd], m->payload, m->len);
	DIE(ret == -1, "write");
	return ret;
}

int get_packet(packet *m) {
	int res;
	fd_set set;

	FD_ZERO(&set);
	while (1) {
		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			FD_SET(interfaces[i], &set);
		}

		res = select(interfaces[ROUTER_NUM_INTERFACES - 1] + 1, &set, NULL, NULL, NULL);
		DIE(res == -1, "select");

		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			if (FD_ISSET(interfaces[i], &set)) {
				socket_receive_message(interfaces[i], m);
				m->interface = i;
				return 0;
			}
		}
	}
	return -1;
}

char *get_interface_ip(int interface) {
	struct ifreq ifr;
	sprintf(ifr.ifr_name, "r-%u", interface);
	ioctl(interfaces[interface], SIOCGIFADDR, &ifr);
	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

int get_interface_mac(int interface, uint8_t *mac) {
	struct ifreq ifr;
	sprintf(ifr.ifr_name, "r-%u", interface);
	ioctl(interfaces[interface], SIOCGIFHWADDR, &ifr);
	memcpy(mac, ifr.ifr_addr.sa_data, 6);
	return 1;
}

void init() {
	int s0 = get_sock("r-0");
	int s1 = get_sock("r-1");
	int s2 = get_sock("r-2");
	int s3 = get_sock("r-3");
	interfaces[0] = s0;
	interfaces[1] = s1;
	interfaces[2] = s2;
	interfaces[3] = s3;
}

/* Returns size if successful. */
long read_rtable(struct route_table_entry **rtable) {
    long size = DEFAULT; // Will contains the total allocated size of *rtable[]
    long i = 0;          // Will contains the actual amount of written cells of *rtable[]

    if (*rtable != NULL) {
        free(*rtable);
        *rtable = NULL;
    }

    *rtable = (struct route_table_entry *)malloc(size * sizeof(struct route_table_entry));

    FILE *fp = fopen("rtable.txt", "r");
    DIE(fp == NULL, "Couldn't open file \"rtable.txt\"");

    char buff1[20];
    char buff2[20];
    char buff3[20];

    int tmp;

    while (fscanf(fp, "%s %s %s %d", buff1, buff2, buff3, &tmp) != EOF) {
        if (i == size) {
            size *= 2;
            *rtable = (struct route_table_entry *)realloc(*rtable, size * sizeof(struct route_table_entry));
        }
        (*rtable)[i].prefix = inet_addr(buff1);
        (*rtable)[i].next_hop = inet_addr(buff2);
        (*rtable)[i].mask = inet_addr(buff3);
        (*rtable)[i].interface = tmp;
        i++;
    }

    fclose(fp);
    return i;
}

/**
 * Adds to arp_table, the mac_buff parameter and spa parameter.
 */
void update_arp_table(struct arp_entry **arp_table, long *size, uint8_t *mac_buff, u_char *spa) {
    struct in_addr ip_holder;
    if (*arp_table == NULL) {
        *size += 1;
        *arp_table = (struct arp_entry *)malloc(*size * sizeof(struct arp_entry));
    } else {
        *size += 1;
        *arp_table = (struct arp_entry *)realloc(*arp_table, *size * sizeof(struct arp_entry));
    }

    char buff[20];
    sprintf(buff, "%d.%d.%d.%d", spa[0], spa[1], spa[2], spa[3]);

    inet_aton(buff, &ip_holder);
    (*arp_table)[*size - 1].ip = ip_holder.s_addr;
    for (int i = 0; i < MACPIECES; i++) {
        (*arp_table)[*size - 1].mac[i] = mac_buff[i];
    }
}

uint16_t checksum(void *vdata, size_t length) {
    // Cast the data pointer to one that can be indexed.
    char *data = (char *)vdata;

    // Initialise the accumulator.
    uint64_t acc = 0xffff;

    // Handle any partial block at the start of the data.
    unsigned int offset = ((uintptr_t)data) & 3;
    if (offset) {
        size_t count = 4 - offset;
        if (count > length) {
            count = length;
        }
        uint32_t word = 0;
        memcpy(offset + (char *)&word, data, count);
        acc += ntohl(word);
        data += count;
        length -= count;
    }

    // Handle any complete 32-bit blocks.
    char *data_end = data + (length & ~3);
    while (data != data_end) {
        uint32_t word;
        memcpy(&word, data, 4);
        acc += ntohl(word);
        data += 4;
    }
    length &= 3;

    // Handle any partial block at the end of the data.
    if (length) {
        uint32_t word = 0;
        memcpy(&word, data, length);
        acc += ntohl(word);
    }

    // Handle deferred carries.
    acc = (acc & 0xffffffff) + (acc >> 32);
    while (acc >> 16) {
        acc = (acc & 0xffff) + (acc >> 16);
    }

    // If the data began at an odd byte address
    // then reverse the byte order to compensate.
    if (offset & 1) {
        acc = ((acc & 0xff00) >> 8) | ((acc & 0x00ff) << 8);
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

/**
 * Returns raised num to power of ten, count times.
 */
u_char to_ten_pow(u_char num, int count) {
    u_char result = num - 48; // 0 char is 48 decimal.
    for (int i = 0; i < count; i++) {
        result *= 10;
    }
    return result;
}

/**
 * convert_ip - Convert ASCII string "192.168.1.0" to a string of
 * u_char result[0] = 192, result[1] = 168, result[2] = 1, result[3] = 0
 * returns the new string result in this example.
 */
u_char *convert_ip(const char *ip) {
    u_char *c_ip = (u_char *)malloc(PACOUNT * sizeof(u_char));
    int count = 0;
    int count2 = PACOUNT - 1;
    u_char tmp = 0;
    for (int i = strlen(ip) - 1; i >= 0; i--) {

        if (ip[i] == '.') {
            c_ip[count2] = tmp;
            tmp = 0;
            count = 0;
            count2--;
            continue;
        }
        tmp += to_ten_pow(ip[i], count);
        count++;
        if (i == 0) {
            c_ip[count2] = tmp;
        }
    }
    return c_ip;
}

static int hex2num(char c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}
int hex2byte(const char *hex) {
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}
/**
 * hwaddr_aton - Convert ASCII string to MAC address (colon-delimited format)
 * @txt: MAC address as a string (e.g., "00:11:22:33:44:55")
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: 0 on success, -1 on failure (e.g., string not a MAC address)
 */
int hwaddr_aton(const char *txt, uint8_t *addr) {
	int i;
	for (i = 0; i < 6; i++) {
		int a, b;
		a = hex2num(*txt++);
		if (a < 0)
			return -1;
		b = hex2num(*txt++);
		if (b < 0)
			return -1;
		*addr++ = (a << 4) | b;
		if (i < 5 && *txt++ != ':')
			return -1;
	}
	return 0;
}
