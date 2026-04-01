#include "util.h"
#include <signal.h>

struct server { int dummy; } redserver;
volatile sig_atomic_t server_running = 1;

int main() {
    char ip[NI_MAXHOST];
    char mac[18];
    char ifname[IFNAMSIZ];

    /* Dynamic detection */
    if (get_production_ip(ip, ifname) == 0) {
        printf("Detected Interface : %s\n", ifname);
        printf("Detected IP        : %s\n", ip);

        if (get_production_mac(ifname, mac) == 0) {
            printf("Detected MAC       : %s\n", mac);
        }
    } else {
        fprintf(stderr, "Error: No active non-loopback interface found.\n");
    }

    return 0;
}