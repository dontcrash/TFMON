#include "helper.h"
#include <pthread.h>
#include "libs/mongoose.h"

struct packet {
    char protocol[10];
    char source_ip[20];
    int source_port;
    char destination_ip[20];
    int destination_port;
    int packet_size_bytes;
};

//TODO This cannot be done this way as it is a hard limit and when full will crash
struct packet packets[1024000];

int num_packets = 0;

void add_packet(char* protocol, char* source_ip, int source_port, char* destination_ip, int destination_port, int packet_size_bytes) {
    strcpy(packets[num_packets].protocol, protocol);
    strcpy(packets[num_packets].source_ip, source_ip);
    packets[num_packets].source_port = source_port;
    strcpy(packets[num_packets].destination_ip, destination_ip);
    packets[num_packets].destination_port = destination_port;
    packets[num_packets].packet_size_bytes = packet_size_bytes;
    num_packets++;
}

int compare_packets_by_sent(const void* a, const void* b) {
    const struct packet* pa = (const struct packet*)a;
    const struct packet* pb = (const struct packet*)b;
    return strcmp(pa->source_ip, pb->source_ip);
}

static void ev_handler(struct mg_connection *nc, int ev, void *ev_data, void *user_data) {
    if (ev == MG_EV_HTTP_MSG) {
        qsort(packets, num_packets, sizeof(struct packet), compare_packets_by_sent);
        int i = num_packets - 1; // start from the end of the array
        char top_ips[1000] = "";
        int count = 0;
        while (i >= 0 && count < 10) { // limit to top 10 IP addresses
            char current_ip[20];
            strcpy(current_ip, packets[i].source_ip);
            int packets_sent = 1;
            i--;
            while (i >= 0 && strcmp(current_ip, packets[i].source_ip) == 0) {
                packets_sent++;
                i--;
            }
            char ip_str[100];
            sprintf(ip_str, "%s - %d packets<br>", current_ip, packets_sent);
            strcat(top_ips, ip_str);
            count++;
        }
        mg_http_reply(nc, 200, "Content-Type: text/html\r\n", "<html><body>Top IP addresses by packets sent:<br>%s</body></html>", top_ips);
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
