#include "helper.h"

const char* get_protocol_name(int protocol_number) {
    struct protoent* proto = getprotobynumber(protocol_number);
    if (proto != NULL) {
        return proto->p_name;
    } else {
        return "unknown";
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct icmphdr *icmp_header;
    u_int ip_len;

    // Get IP header
    ip_header = (struct iphdr*)(packet + sizeof(struct ether_header));
    ip_len = ip_header->ihl * 4;

    // Convert protocool number into a string
    const char* protocol_name = get_protocol_name(ip_header->protocol);

    // Get source and destination IP addresses
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dst_ip, INET_ADDRSTRLEN);

    // Get source and destination port numbers
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    if (ip_header->protocol == IPPROTO_TCP) {
        tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_len);
        src_port = ntohs(tcp_header->source);
        dst_port = ntohs(tcp_header->dest);
    } else if (ip_header->protocol == IPPROTO_UDP) {
        udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + ip_len);
        src_port = ntohs(udp_header->source);
        dst_port = ntohs(udp_header->dest);
    }

    // Get packet size in bytes
    uint32_t packet_size = header->len;

    // Print packet information
    printf("%s,%s,%d,%s,%d,%d\n", protocol_name, src_ip, src_port, dst_ip, dst_port, packet_size);
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    char *dev = get_interface(argc, argv);

    // Get network address and mask
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    // Open capture device
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    // Compile and apply the filter
    if (pcap_compile(handle, &fp, "ip and (tcp or udp or icmp)", 0, net) == -1) {
        fprintf(stderr, "Couldn't compile filter: %s\n", pcap_geterr(handle));
        return EXIT_FAILURE;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't set filter: %s\n", pcap_geterr(handle));
        return EXIT_FAILURE;
    }

    // Start capturing packets
    pcap_loop(handle, -1, packet_handler, NULL);

    // Cleanup
    pcap_freecode(&fp);
    pcap_close(handle);

    return EXIT_SUCCESS;
}
