#include "helper.h"
#include <pthread.h>
#include "libs/mongoose.h"

#define MAX_PACKETS 1000000
#define TOP_LIST 20

int total_packets = 0;

struct packet {
    char protocol[10];
    char source_ip[20];
    int source_port;
    char destination_ip[20];
    int destination_port;
    int packet_size_bytes;
};


// Log x number of packets before looping back
struct packet packets[MAX_PACKETS];

int packet_index = 0;

void add_packet(char* protocol, char* source_ip, int source_port, char* destination_ip, int destination_port, int packet_size_bytes) {
    strcpy(packets[packet_index].protocol, protocol);
    strcpy(packets[packet_index].source_ip, source_ip);
    packets[packet_index].source_port = source_port;
    strcpy(packets[packet_index].destination_ip, destination_ip);
    packets[packet_index].destination_port = destination_port;
    packets[packet_index].packet_size_bytes = packet_size_bytes;
    packet_index++;
    if(packet_index == MAX_PACKETS) {
        packet_index = 0;
    }
    ++total_packets;
}

int compare_packets_by_sent(const void* a, const void* b) {
    const struct packet* pa = (const struct packet*)a;
    const struct packet* pb = (const struct packet*)b;
    return strcmp(pa->source_ip, pb->source_ip);
}

static void ev_handler(struct mg_connection *nc, int ev, void *ev_data, void *user_data) {
    if (ev == MG_EV_HTTP_MSG) {
        qsort(packets, packet_index, sizeof(struct packet), compare_packets_by_sent);
        int i = packet_index - 1; // start from the end of the array
        char top_ips[1000] = "";
        int count = 0;
        while (i >= 0 && count < TOP_LIST) {
            char current_ip[20];
            strcpy(current_ip, packets[i].source_ip);
            int packets_sent = 1;
            i--;
            while (i >= 0 && strcmp(current_ip, packets[i].source_ip) == 0) {
                packets_sent++;
                i--;
            }
            char ip_str[100];
            sprintf(ip_str, "<tr><td>%s</td><td>%d</td></tr>", current_ip, packets_sent);
            strcat(top_ips, ip_str);
            count++;
        }
        mg_http_reply(nc, 200, "Content-Type: text/html\r\n", "<html><body>Total packets: %d<br><br>Top IP addresses by packets from last %d packets:<br><table>%s</table></body></html>", total_packets, MAX_PACKETS, top_ips);
    }
}

void *packet_listener_thread(void *dev) {
    char command[256] = "./packet_listener ";
    strcat(command, (char *)dev);

    // Open the process for reading
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error running command: %s\n", command);
        exit(1);
    }

    char output[1024];
    //Loop through output
    while (fgets(output, sizeof(output), fp) != NULL) {
        char* protocol = strtok(output, ",");
        char* source_ip = strtok(NULL, ",");
        int source_port = atoi(strtok(NULL, ","));
        char* destination_ip = strtok(NULL, ",");
        int destination_port = atoi(strtok(NULL, ","));
        int packet_size_bytes = atoi(strtok(NULL, ",\n"));
        add_packet(protocol, source_ip, source_port, destination_ip, destination_port, packet_size_bytes);
    }

    // Close the process
    pclose(fp);

    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {

    char *dev = get_interface(argc, argv);

    // Start the packet listener thread
    pthread_t listener_tid;
    if (pthread_create(&listener_tid, NULL, packet_listener_thread, dev) != 0) {
        fprintf(stderr, "Error creating packet listener thread\n");
        exit(1);
    }

    // Start the web server
    struct mg_mgr mgr;
    mg_mgr_init(&mgr);

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", LISTEN_PORT);

    char listen_url[64];
    snprintf(listen_url, sizeof(listen_url), "http://0.0.0.0:%d", LISTEN_PORT);    

    struct mg_connection *nc = mg_http_listen(&mgr, listen_url, ev_handler, &mgr);
    if (nc == NULL) {
        fprintf(stderr, "Error starting web server on port %d\n", LISTEN_PORT);
        exit(1);
    }

    printf("Listening on port %d\n", LISTEN_PORT);

    for (;;) mg_mgr_poll(&mgr, 1000);
    mg_mgr_free(&mgr);

    return 0;
}
