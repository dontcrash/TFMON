#include "helper.h"
#include <pthread.h>
#include <stdbool.h>
#include "libs/mongoose.h"

#define MAX_IPS 1000000

int total_packets = 0;

struct packet {
    char protocol[10];
    char source_ip[20];
    int source_port;
    char destination_ip[20];
    int destination_port;
    int packet_size_bytes;
};

struct stats {
    char ip[20];
    int total_packets;
    int total_bytes;
    int num_protocols;
    char protocols[10][10];
};

struct stats ip_stats[MAX_IPS];
int num_ips = 0;

//TODO save ip_stats to a file when closing and load it if it exists in the main void

static void ev_handler(struct mg_connection *nc, int ev, void *ev_data, void *user_data) {
    if (ev == MG_EV_HTTP_MSG) {
        char *header = "Content-Type: text/html\r\n";
        char unique_text[100];
        sprintf(unique_text, "IP addresses: %d", num_ips);
        char packet_text[100];
        sprintf(packet_text, "Total packets: %d", total_packets);
        mg_http_reply(nc, 200, header, "<html><body>%s<br>%s</body></html>", unique_text, packet_text);
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
        ++total_packets;

        // check if this IP already exists in our stats array
        int ip_index = -1;
        for (int i = 0; i < num_ips; ++i) {
            if (strcmp(ip_stats[i].ip, source_ip) == 0) {
                ip_index = i;
                break;
            }
        }

        if (ip_index == -1) {
            // new IP, initialize stats
            strncpy(ip_stats[num_ips].ip, source_ip, sizeof(ip_stats[num_ips].ip) - 1);
            ip_stats[num_ips].total_packets = 0;
            ip_stats[num_ips].total_bytes = 0;
            ip_stats[num_ips].num_protocols = 0;
            ++num_ips;
        }

        // update stats
        ip_stats[ip_index].total_packets += 1;
        ip_stats[ip_index].total_bytes += packet_size_bytes;

        // check if protocol already exists
        int protocol_index = -1;
        for (int i = 0; i < ip_stats[ip_index].num_protocols; ++i) {
            if (strcmp(ip_stats[ip_index].protocols[i], protocol) == 0) {
                protocol_index = i;
                break;
            }
        }

        if (protocol_index == -1) {
            // new protocol for this IP, add to protocols array
            strncpy(ip_stats[ip_index].protocols[ip_stats[ip_index].num_protocols], protocol, sizeof(ip_stats[ip_index].protocols[0]) - 1);
            ++ip_stats[ip_index].num_protocols;
        }
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
