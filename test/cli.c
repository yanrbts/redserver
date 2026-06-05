/*
 * Copyright (c) 2026-2026, CLI
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include "cmd.h"
#include "linenoise.h"

#define REFLEX_PROMPT   "reflex> " 

/* Sub-command dictionaries for deeper completion */
static const char *set_subs[] = {"interval", "logpkt", "debug", "auth", NULL};
static const char *get_subs[] = {"config", "pktstats", "heartbeat", NULL};
static const char *pcap_subs[] = {"filter", "capture", NULL};
static const char *help_subs[] = {"SET", "GET", "PCAP", NULL};

/* Professional UI Data Structure with Sub-command Support */
static struct {
    const char *name;
    const char *hint;
    const char **subs;    /* Pointer to sub-command array, NULL if none */
    const char *sub_hint;
} cli_ui_data[] = {
    {"SET",    " <key> <value>", set_subs,   " <value>"},
    {"GET",    " <key>",         get_subs,   NULL},       
    {"PCAP",   " <key> <value>", pcap_subs,  " <value>"},
    {"STATUS", " (Check server health)", NULL, NULL},
    {"HELP",   " [command]",      help_subs,  NULL},
    {"EXIT",   " (Close console)", NULL,     NULL},
    {NULL, NULL, NULL, NULL}
};

static void reflex_show_banner(void) {
    const char *VERSION = "1.0.2";
    const char *AUTHOR  = "yanrb";
    const char *PROJECT = "Reflex High-Performance Control System";

    const char *ascii_art = 
        "  ────╔═╗\n"
        "  ╔╦╦═╣═╬╗╔═╦╦╗\n"
        "  ║╔╣╩╣╔╣╚╣╩╬║╣\n"
        "  ╚╝╚═╩╝╚═╩═╩╩╝\n";

    printf("\n%s%s%s\n", C_GREEN, ascii_art, C_RESET);
    
    printf("  %sProject :%s %s%s%s\n", C_GRAY,  C_RESET, C_GRAY, PROJECT, C_RESET);
    printf("  %sVersion :%s %s%s%s\n", C_GRAY,  C_RESET, C_GRAY, VERSION, C_RESET);
    printf("  %sAuthor  :%s %s%s%s\n", C_GRAY,  C_RESET, C_GRAY, AUTHOR,  C_RESET);
    printf("  %sLicense :%s %sCopyright (c) 2026, All Rights Reserved%s\n", 
           C_GRAY, C_RESET, C_GRAY, C_RESET);
    printf("  %sType 'HELP' for commands, 'EXIT' to quit.%s\n\n", C_GRAY, C_RESET);
}

/**
 * @brief Professional Tab Completion: Handles both Primary and Sub-commands.
 */
static void completion_callback(const char *buf, linenoiseCompletions *lc) {
    if (!buf) return;

    /* Create a mutable copy for tokenization */
    char *buf_copy = strdup(buf);
    char *tokens[3] = {NULL, NULL, NULL};
    int token_count = 0;

    /* Split input by spaces to detect level */
    char *p = buf_copy;
    char *token = strtok(p, " ");
    while (token && token_count < 2) {
        tokens[token_count++] = token;
        token = strtok(NULL, " ");
    }

    /* Logic 1: Completing the Primary Command (e.g., "S" -> "SET") */
    if (token_count <= 1 && buf[strlen(buf) - 1] != ' ') {
        for (int i = 0; cli_ui_data[i].name; i++) {
            if (strncasecmp(buf, cli_ui_data[i].name, strlen(buf)) == 0) {
                linenoiseAddCompletion(lc, cli_ui_data[i].name);
            }
        }
    } 
    /* Logic 2: Completing the Sub-command (e.g., "SET i" -> "SET interval") */
    else {
        const char *primary = tokens[0];
        const char *sub_prefix = (token_count == 2) ? tokens[1] : "";

        for (int i = 0; cli_ui_data[i].name; i++) {
            if (strcasecmp(primary, cli_ui_data[i].name) == 0 && cli_ui_data[i].subs) {
                const char **subs = cli_ui_data[i].subs;
                for (int j = 0; subs[j]; j++) {
                    if (strncasecmp(sub_prefix, subs[j], strlen(sub_prefix)) == 0) {
                        char full_line[128];
                        /* Format: "PRIMARY SUB" for seamless completion replacement */
                        snprintf(full_line, sizeof(full_line), "%s %s", cli_ui_data[i].name, subs[j]);
                        linenoiseAddCompletion(lc, full_line);
                    }
                }
                break;
            }
        }
    }
    free(buf_copy);
}

/**
 * @brief Context-aware Hints: Dynamically routes hints based on sub_hint properties.
 */
static char *hints_callback(const char *buf, int *color, int *bold) {
    *color = 90; /* Dark Gray ghost text color descriptor */
    *bold = 0;
    if (!buf || !*buf) return NULL;

    /* 1. Tokenize input snapshot to evaluate architectural boundary constraints */
    char *buf_copy = strdup(buf);
    char *tokens[3] = {NULL, NULL, NULL};
    int token_count = 0;
    
    char *token = strtok(buf_copy, " ");
    while (token && token_count < 3) {
        tokens[token_count++] = token;
        token = strtok(NULL, " ");
    }
    
    size_t buf_len = strlen(buf);
    int ends_with_space = (buf_len > 0 && buf[buf_len - 1] == ' ');
    char *primary = tokens[0];

    /* 2. Traverse data matrix to isolate top-tier node signatures */
    for (int i = 0; cli_ui_data[i].name; i++) {
        if (strcasecmp(primary, cli_ui_data[i].name) == 0) {
            
            /* Scenario A: User typed exactly the primary token (e.g., "SET" without space).
             * Route default generic hint immediately.
             */
            if (token_count == 1 && !ends_with_space) {
                free(buf_copy);
                return (char *)cli_ui_data[i].hint;
            }
            
            /* Scenario B: Active tracking during second-tier initialization or partial matching.
             * (e.g., "SET " or "SET i", "GET con" where command is incomplete).
             */
            if ((token_count == 1 && ends_with_space) || 
                (token_count == 2 && !ends_with_space)) {
                
                const char *sub_part = (token_count == 2) ? tokens[1] : "";
                size_t sub_len = strlen(sub_part);
                
                int is_partial_sub = 0;
                if (cli_ui_data[i].subs && sub_len > 0) {
                    for (int j = 0; cli_ui_data[i].subs[j]; j++) {
                        /* Validate if token matches sub-command matrix slice as a prefix */
                        if (strncasecmp(sub_part, cli_ui_data[i].subs[j], sub_len) == 0 &&
                            strcasecmp(sub_part, cli_ui_data[i].subs[j]) != 0) {
                            is_partial_sub = 1;
                            break;
                        }
                    }
                }

                /* Keep emitting primary hint block if no sub-command has consolidated yet */
                if (sub_len == 0 || is_partial_sub) {
                    free(buf_copy);
                    return (char *)cli_ui_data[i].hint;
                }
            }

            /* Scenario C: Core Target Realignment.
             * User has completely matched a valid sub-command descriptor (e.g., "GET config" or "SET interval").
             */
            if ((token_count == 2) || (token_count == 3 && !ends_with_space)) {
                const char *exact_sub = tokens[1];
                
                if (cli_ui_data[i].subs) {
                    for (int j = 0; cli_ui_data[i].subs[j]; j++) {
                        /* Match verified. Delegate response to specific tail parameters configuration */
                        if (strcasecmp(exact_sub, cli_ui_data[i].subs[j]) == 0) {
                            free(buf_copy);
                            /* Dynamically route tailored metadata string (e.g. " <value>" vs NULL) */
                            return (char *)cli_ui_data[i].sub_hint;
                        }
                    }
                }
            }
            break;
        }
    }

    free(buf_copy);
    return NULL;
}

int main() {
    char *line;
    linenoiseSetCompletionCallback(completion_callback);
    linenoiseSetHintsCallback(hints_callback);
    linenoiseHistoryLoad("/tmp/reflex_history");

    reflex_show_banner();

    while ((line = linenoise(REFLEX_PROMPT)) != NULL) {
        if (line[0] != '\0') {
            if (strcasecmp(line, "exit") == 0 || strcasecmp(line, "quit") == 0) {
                free(line);
                break;
            }

            int fd = cmd_transport_connect(SOCKET_PATH);
            if (fd >= 0) {
                cmd_transport_send(fd, 0, line, strlen(line));
                afuinx_header_t h; 
                char *res = NULL;
                if (cmd_transport_recv(fd, &h, &res) == 0) {
                    if (res) {
                        printf("%s\n", res);
                        free(res);
                    }
                }
                close(fd);
            } else {
                fprintf(stderr, "Error: Could not connect to engine at %s\n", SOCKET_PATH);
            }

            linenoiseHistoryAdd(line);
            linenoiseHistorySave("/tmp/reflex_history");
        }
        free(line);
    }
    return 0;
}