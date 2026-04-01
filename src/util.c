#include <time.h>
#include "util.h"

/**
 * @brief Retrieves the raw binary MAC address and IPv4 address of the first active interface.
 * * This function iterates through available network interfaces to find the first 
 * non-loopback IPv4-enabled interface. It extracts the IP address in network byte 
 * order and the hardware MAC address in its 6-byte binary representation.
 *
 * @param mac_bin Pointer to a buffer to store the 6-byte binary MAC address.
 * @param ip_bin  Pointer to a uint32_t to store the IPv4 address (Network Byte Order).
 * @return int    Returns 0 on success, or -1 if no suitable interface is found 
 * or a system call fails.
 */
int get_interface_binary_info(uint8_t *mac_bin, uint32_t *ip_bin) {
    struct ifaddrs *ifaddr, *ifa;
    int found = -1;

    /* Get the linked list of all network interfaces */
    if (getifaddrs(&ifaddr) == -1) {
        return -1;
    }

    /* Traverse the linked list to find a valid IPv4 interface */
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        /* Check for IPv4 family and ensure it is not a Loopback interface */
        if (ifa->ifa_addr->sa_family == AF_INET && !(ifa->ifa_flags & IFF_LOOPBACK)) {
            
            /* 1. Extract the binary IP address (4 bytes) */
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            *ip_bin = sa->sin_addr.s_addr; /* Already in Network Byte Order */

            /* 2. Extract the hardware MAC address (6 bytes binary) */
            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd >= 0) {
                struct ifreq ifr;
                /* Ensure interface name fits in ifr_name buffer */
                strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
                ifr.ifr_name[IFNAMSIZ - 1] = '\0';

                /* Perform I/O Control call to fetch Hardware Address */
                if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
                    memcpy(mac_bin, ifr.ifr_hwaddr.sa_data, 6);
                    found = 0;
                }
                close(fd);
            }
            
            /* Stop searching after the first successful match */
            if (found == 0) break;
        }
    }

    /* Clean up allocated memory */
    freeifaddrs(ifaddr);
    return found;
}

/**
 * Automatically finds the first active non-loopback IPv4 interface.
 * @param ip_buf  Output buffer for IP string (min 16 bytes).
 * @param if_name Output buffer for interface name (min IFNAMSIZ).
 * @return 0 on success, -1 on failure.
 */
int get_production_ip(char *ip_buf, char *if_name) {
    struct ifaddrs *ifaddr, *ifa;
    int found = -1;

    /* Retrieve the linked list of interface addresses */
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    /* Walk through the linked list */
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        /* Look for IPv4 (AF_INET) and skip Loopback interface */
        if (ifa->ifa_addr->sa_family == AF_INET && !(ifa->ifa_flags & IFF_LOOPBACK)) {
            
            /* Convert binary IP to human-readable string */
            if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                           ip_buf, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0) {
                
                /* Copy the interface name to the output buffer */
                strncpy(if_name, ifa->ifa_name, IFNAMSIZ - 1);
                found = 0;
                break; 
            }
        }
    }

    /* Free the memory allocated by getifaddrs */
    freeifaddrs(ifaddr);
    return found;
}

/**
 * Retrieves the hardware (MAC) address using the specific interface name.
 * @param if_name The interface name (e.g., "ens33").
 * @param mac_buf Output buffer for MAC string (min 18 bytes).
 * @return 0 on success, -1 on failure.
 */
int get_production_mac(const char *if_name, char *mac_buf) {
    struct ifreq ifr;
    int fd;
    unsigned char *ptr;

    /* Create a dummy socket for ioctl calls */
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    /* Define which interface to query */
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);

    /* Fetch Hardware Address (MAC) */
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }

    close(fd);
    ptr = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    
    /* Format binary MAC to standard hex notation */
    sprintf(mac_buf, "%02x:%02x:%02x:%02x:%02x:%02x",
            ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);

    return 0;
}

uint64_t get_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (ts.tv_nsec / 1000000);
}

int ip_pton(const char *ip_str, uint32_t *out_ip) {
    if (!ip_str || !out_ip) return -1;
    
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        return -1;
    }
    
    *out_ip = addr.s_addr;
    return 0;
}

int ip_ntop(uint32_t ip_bin, char *out_str, size_t size) {
    if (!out_str || size < INET_ADDRSTRLEN) return -1;

    struct in_addr addr;
    addr.s_addr = ip_bin;

    if (inet_ntop(AF_INET, &addr, out_str, size) == NULL) {
        return -1;
    }

    return 0;
}