#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <math.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <unistd.h>

#define MAX_DEV_LEN 256
#define LISTEN_PORT 8371

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

char* get_process_name_by_port(int port) {
    char command[1024];
    snprintf(command, sizeof(command), "sudo netstat -plntu | grep -E ':%d\\s' | awk '{print $7}'", port);
    printf("Command: %s\n", command); // debug line
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen");
        exit(1);
    }

    static char process_name[2048]; // Increased buffer size
    if (fgets(process_name, sizeof(process_name), fp) != NULL) {
        printf("Process name: %s\n", process_name); // debug line
        // Trim newline from end of process name
        size_t len = strlen(process_name);
        if (len > 0 && process_name[len-1] == '\n') {
            process_name[len-1] = '\0';
        }
    } else {
        printf("Process name: Unknown\n"); // debug line
        strcpy(process_name, "Unknown");
    }

    pclose(fp);

    return process_name;
}

char* convert_data_size(double total_kb, double *data_received) {
    const char *units[] = {"kb", "KB", "Mb", "MB", "Gb", "GB", "Tb", "TB"};
    const int num_units = 8;
    const long long base = 1024;

    char* data_unit = (char*) malloc(sizeof(char) * 3);

    if (total_kb < base) {
        *data_received = total_kb/8;
        strcpy(data_unit, units[0]);
        return data_unit;
    }

    int exp = log(total_kb) / log(base);
    if (exp > num_units / 2) exp = num_units / 2;

    double converted = total_kb / pow(base, exp);
    *data_received = converted;
    strcpy(data_unit, units[exp * 2 + (converted >= base)]);

    return data_unit;
}

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

char* get_interface(int argc, char *argv[]) {
    char dev[MAX_DEV_LEN];
    if (argc == 2) {
        strncpy(dev, argv[1], MAX_DEV_LEN);
    } else if (argc == 1) {
        // Prompt the user for an interface name
        printf("Enter the interface name to capture packets from (e.g. enp3s0f0): ");
        fflush(stdout);
        if (fgets(dev, MAX_DEV_LEN, stdin) == NULL) {
            fprintf(stderr, "Error reading interface name\n");
            exit(1);
        }
        // Remove trailing newline if present
        if (dev[strlen(dev) - 1] == '\n') {
            dev[strlen(dev) - 1] = '\0';
        }
        if (strlen(dev) == 0) {
            fprintf(stderr, "No interface specified\n");
            exit(1);
        }
    } else {
        fprintf(stderr, "Usage: %s [interface]\n", argv[0]);
        exit(1);
    }
    return strdup(dev);
}
