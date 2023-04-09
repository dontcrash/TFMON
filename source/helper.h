#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

#define MAX_DEV_LEN 256
#define LISTEN_PORT 8371

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
