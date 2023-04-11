#include "helper.h"
#include <pthread.h>
#include <stdbool.h>
#include "libs/mongoose.h"

#define MAX_IPS 10000000
#define TOP_LIST 15

long long int total_packets = 0;

struct packet {
    char protocol[10];
    char source_ip[20];
    int source_port;
    char destination_ip[20];
    int destination_port;
    double packet_size_bytes;
};

struct stats {
    char ip[20];
    long long int total_packets;
    double total_kilobytes;
    int num_protocols;
    char protocols[10][10];
};

struct stats stats[MAX_IPS];
int num_ips = 0;

int cmp_stats_by_bytes_desc(const void* a, const void* b) {
    const struct stats* sa = (const struct stats*)a;
    const struct stats* sb = (const struct stats*)b;

    int a_kilobytes = (int)(sa->total_kilobytes);
    int b_kilobytes = (int)(sb->total_kilobytes);

    if (a_kilobytes < b_kilobytes) {
        return 1;
    }
    else if (a_kilobytes > b_kilobytes) {
        return -1;
    }
    else {
        return 0;
    }
}

//TODO save stats to a file when closing and load it if it exists in the main void

static void ev_handler(struct mg_connection *nc, int ev, void *ev_data, void *user_data) {
    if (ev == MG_EV_HTTP_MSG) {
        char *header = "Content-Type: text/html\r\n";

        // Sort IP stats by total bytes in descending order
        qsort(stats, num_ips, sizeof(struct stats), cmp_stats_by_bytes_desc);

        //CSS
        char *head_html = "<title>TFMON</title><style>td{width:150px;}</style>";

        // Generate HTML to display top IP addresses and total data they have sent
        char top_ips_html[2048];
        snprintf(top_ips_html, sizeof(top_ips_html), "<table><tr><td><b>IP Address</b></td><td><b>Data received</b></td></tr>");
        for (int i = 0; i < TOP_LIST && i < num_ips; ++i) {
            double total_kb = stats[i].total_kilobytes;
            // Convert unit here based on size, either show in kB or mB
            double data_received = 0;
            char *data_unit = "";
            if(total_kb < 8) {
                // Convert from kB to kb
                data_received = total_kb*8;
                data_unit = "kb";
            } else if(total_kb < 125) {
                // Show in kB
                data_received = total_kb;
                data_unit = "kB";
            } else if(total_kb < 125000) {
                // Convert to Mb
                data_received = total_kb/125;
                data_unit = "Mb";
            } else {
                data_received = total_kb/125000;
                data_unit = "Gb";
            }
            snprintf(top_ips_html + strlen(top_ips_html), sizeof(top_ips_html) - strlen(top_ips_html), "<tr><td><a href=\"https://ipgeolocation.io/ip-location/%s\">%s</a></td><td>%.2f %s</td></tr>", stats[i].ip, stats[i].ip, data_received, data_unit);
        }
        snprintf(top_ips_html + strlen(top_ips_html), sizeof(top_ips_html) - strlen(top_ips_html), "</table>");

        // Generate HTML to display total packets and unique IP addresses
        char stats_html[100];
        snprintf(stats_html, sizeof(stats_html), "Total packets: %lld<br>Unique IP addresses: %d", total_packets, num_ips);

        // Send HTTP response with generated HTML
        mg_http_reply(nc, 200, header, "<html><head>%s</head><body>%s<br><br>%s</body></html>", head_html, stats_html, top_ips_html);
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
        double packet_size_bytes = atof(strtok(NULL, ",\n"));
        ++total_packets;

        // check if this IP already exists in our stats array
        int ip_index = -1;
        for (int i = 0; i < num_ips; ++i) {
            if (strcmp(stats[i].ip, source_ip) == 0) {
                ip_index = i;
                break;
            }
        }

        if (ip_index == -1) {
            // new IP, initialize stats
            strncpy(stats[num_ips].ip, source_ip, sizeof(stats[num_ips].ip) - 1);
            stats[num_ips].total_packets = 0;
            stats[num_ips].total_kilobytes = 0;
            stats[num_ips].num_protocols = 0;
            ++num_ips;
        }

        // update stats
        stats[ip_index].total_packets += 1;
        //Use 1000, pcap_pkthdr Struct references the len int as bytes (1000)
        stats[ip_index].total_kilobytes += packet_size_bytes/1000;

        // check if protocol already exists
        int protocol_index = -1;
        for (int i = 0; i < stats[ip_index].num_protocols; ++i) {
            if (strcmp(stats[ip_index].protocols[i], protocol) == 0) {
                protocol_index = i;
                break;
            }
        }
        if (protocol_index == -1) {
            // new protocol for this IP, add to protocols array
            strncpy(stats[ip_index].protocols[stats[ip_index].num_protocols], protocol, sizeof(stats[ip_index].protocols[0]) - 1);
            ++stats[ip_index].num_protocols;
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
