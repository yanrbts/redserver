#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "5gc.h"
#include "log.h"

/* Global pointer to handle cleanup during SIGINT (Ctrl+C) */
static gc_ctx_t *g_service_ctx = NULL;

/**
 * @brief Signal handler for graceful shutdown.
 * @param sig Signal number.
 */
void handle_sigint(int sig) {
    printf("\n[Signal] Captured SIGINT (%d). Cleaning up...\n", sig);
    if (g_service_ctx) {
        /* Stop the thread and free memory using your provided interfaces */
        gc_service_destroy(g_service_ctx);
    }
    exit(0);
}

/**
 * @brief User-defined callback to handle state transitions.
 * @param ctx Pointer to the context.
 * @param state The new state of the service.
 */
void my_app_on_state_change(gc_ctx_t *ctx, gc_state_e state) {
    const char *state_names[] = {
        "DISCOVERY", 
        "REGISTER", 
        "HEARTBEAT"
    };

    printf("\n>>>> [EVENT] State Changed to: %s <<<<\n", state_names[state]);

    if (state == GC_STATE_HEARTBEAT) {
        char ip_str[16];
        /* Accessing the switch node info stored in the context */
        inet_ntop(AF_INET, &ctx->node.ipv4, ip_str, sizeof(ip_str));
        printf(">>>> [INFO] Connected to Server IP: %s\n", ip_str);
    }
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    /* Set up Signal Handling */
    signal(SIGINT, handle_sigint);

    printf("=== 5GC Service Industrial Test Client ===\n");
    printf("Press Ctrl+C to terminate the program.\n\n");

    /* 1. Create the service instance
     * port: 50001
     * is_black: false (Switch mode) 
     */
    g_service_ctx = gc_service_create(0, 50001, false);
    if (!g_service_ctx) {
        fprintf(stderr, "Failed to create 5GC service context.\n");
        return -1;
    }

    /* 2. Set the custom callback 
     * The service will call this function whenever it switches states.
     */
    g_service_ctx->on_state_change = my_app_on_state_change;

    /* 3. Start the background maintenance service 
     * This launches the worker thread to handle Discovery -> Register -> Heartbeat.
     */
    if (gc_service_start(g_service_ctx) != 0) {
        fprintf(stderr, "Failed to start the 5GC service.\n");
        gc_service_destroy(g_service_ctx);
        return -1;
    }

    /* 4. Main Application Loop 
     * The main thread is free to perform other business logic.
     */
    int counter = 0;
    while (1) {
        // Example: Periodically print a heartbeat from the main thread
        // to show that the background thread isn't blocking us.
        if (counter % 10 == 0) {
            printf("[Main Thread] Application is running... (uptime: %ds)\n", counter);
        }
        
        sleep(1);
        counter++;
    }

    return 0;
}