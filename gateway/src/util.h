#ifndef __UTIL_H__
#define __UTIL_H__

#define _GNU_SOURCE     /* To enable NI_MAXHOST in netdb.h */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <sys/socket.h> /* Essential for socket functions */
#include <net/if.h>     /* Essential for IFNAMSIZ and struct ifreq */
#include <arpa/inet.h>
#include <netdb.h>      /* Essential for getnameinfo and NI_MAXHOST */

#ifndef likely
#define likely(x)      __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)    __builtin_expect(!!(x), 0)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

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
int get_interface_binary_info(uint8_t *mac_bin, uint32_t *ip_bin);

/**
 * Automatically finds the first active non-loopback IPv4 interface.
 * @param ip_buf  Output buffer for IP string (min 16 bytes).
 * @param if_name Output buffer for interface name (min IFNAMSIZ).
 * @return 0 on success, -1 on failure.
 */
int get_production_ip(char *ip_buf, char *if_name);

/**
 * Retrieves the hardware (MAC) address using the specific interface name.
 * @param if_name The interface name (e.g., "ens33").
 * @param mac_buf Output buffer for MAC string (min 18 bytes).
 * @return 0 on success, -1 on failure.
 */
int get_production_mac(const char *if_name, char *mac_buf);

/**
 * @brief Get current time in milliseconds since Unix epoch.
 * @return uint64_t Current time in milliseconds.
 */
uint64_t get_now_ms(void);

/**
 * @brief Convert IPv4 address string to binary (network byte order).
 * @param ip_str   Input IPv4 address string (e.g., "192.168.1.1").
 * @param out_ip   Output pointer to store the binary IPv4 address.
 * @return 0 on success, -1 on failure.
 */
int ip_pton(const char *ip_str, uint32_t *out_ip);

/**
 * @brief Convert binary IPv4 address (network byte order) to string.
 * @param ip_bin   Input binary IPv4 address.
 * @param out_str  Output buffer to store the IPv4 address string.
 * @param size     Size of the output buffer.
 * @return 0 on success, -1 on failure.
 */
int ip_ntop(uint32_t ip_bin, char *out_str, size_t size);

/**
 * @brief Calculate the IPv4 header checksum for the given data buffer.
 * @param data Pointer to the buffer containing the IPv4 header.
 * @param len  Length of the buffer (should be at least the size of the IPv4 header).
 * @return The calculated checksum value.
 */
uint16_t ip_calculate_checksum(const void* data, size_t len);

const char *ip_to_str(uint32_t ip);

/**
 * @brief Retrieves the active IPv4 address tied to a specific network interface.
 * @param ifname   The network interface identifier string (e.g., "eth0", "ens33").
 * @param ip_buf   Destination pointer to memory buffer where the IP string will be written.
 * @param buf_len  Size of the destination buffer. Strictly recommended to be >= INET_ADDRSTRLEN (16).
 * @return int     1 on success (IP found and copied safely);
 *                 0 on failure (Interface down, missing IPv4 binding, or invalid parameters).
 * @note Production-grade implementation using getifaddrs() to bypass obsolete ioctl limits.
 *       It guarantees zero buffer overflows and properly ignores non-IPv4 interface links.
 */
int get_interface_ip(const char *ifname, char *ip_buf, size_t buf_len);

#endif