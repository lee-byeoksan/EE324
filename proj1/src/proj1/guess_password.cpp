/*
 * Copyright 2015 Lee, Byeoksan
 * guess_password.cpp
 * EE324 Project1 - Part I (implemented)
 *                - Part II (implemented)
 * Author: 20100667 Lee, Byeoksan
 */

#include <proj1/guess_password.h>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <proj1/msg.h>

#define PROG_NAME "guess_password"
#define OUTPUT_FILE "password.txt"
#define STUDENT_ID 20100667

#define TIMEOUT_SEC 3
#define TIMEOUT_USEC 0
#define MAX_ATTEMPT 3

#define HEADER_SIZE sizeof(struct header_t)
#define QUERY_SIZE sizeof(struct query_t)
#define RESPONSE_SIZE sizeof(struct response_t)

int main(int argc, char *argv[]) {
    int sock;
    uint32_t low = 0, high = UINT32_MAX; /* inclusive range */
    uint32_t guess;
    enum result_t result;

    if (argc < 3) {
        Usage();
        exit(EXIT_FAILURE);
    }

    sock = GetConnectedSocketOrExit(argv[1], argv[2]);
    do {
        guess = (high + low) / 2;
        if (!GuessOnce(sock, STUDENT_ID, guess, &result)) {
            fprintf(stderr, "three requests have been sent but no response\n");
            exit(EXIT_FAILURE);
        }

        if (result == LT) {
            high = guess - 1;
        } else if (result == GT) {
            low = guess + 1;
        }
    } while (result != EQ && result != USER_NOT_REGISTERED && low <= high);
    close(sock);

    if (low > high) {
        /* Something wrong */
        fprintf(stderr, "cannot find the password\n");
        exit(EXIT_FAILURE);
    }

    if (result == USER_NOT_REGISTERED) {
        fprintf(stderr, "the user is not registered\n");
        exit(EXIT_FAILURE);
    }

    if (result == EQ) {
        FILE *out = fopen(OUTPUT_FILE, "w");
        fprintf(out, "%d %d\n", STUDENT_ID, guess);
        fclose(out);
        exit(EXIT_SUCCESS);
    }

    exit(EXIT_FAILURE);
}

void Usage() {
    fprintf(stderr, "Usage: %s <host> <port>\n", PROG_NAME);
}

void PerrorAndExit(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int GetConnectedSocketOrExit(const char *host, const char *port) {
    int sock;
    int gai_error_code;
    struct addrinfo *addr_res = NULL;
    struct addrinfo addr_hint;

    bzero(&addr_hint, sizeof(addr_hint));
    addr_hint.ai_family = AF_INET;
    addr_hint.ai_socktype = SOCK_DGRAM;
    addr_hint.ai_protocol = 0;
    addr_hint.ai_flags |= AI_NUMERICSERV; /* port must be a number */

    /* Get addrinfo */
    gai_error_code = getaddrinfo(host, port, &addr_hint, &addr_res);
    if (gai_error_code) {
        fprintf(stderr, "getaddrinfo: ");
        fprintf(stderr, "%s\n", gai_strerror(gai_error_code));
        exit(EXIT_FAILURE);
    }

    /* We create socket from the first addrinfo result. */
    sock = socket(addr_res->ai_family, addr_res->ai_socktype,
                  addr_res->ai_protocol);
    freeaddrinfo(addr_res);

    if (sock == -1) {
        PerrorAndExit("socket");
    }

    if (connect(sock, addr_res->ai_addr, addr_res->ai_addrlen) == -1) {
        close(sock);
        PerrorAndExit("connect");
    }

    return sock;
}

bool GuessOnce(const int sock, const uint32_t id,
               const uint32_t guess, enum result_t *result) {
    uint8_t req_msg[HEADER_SIZE + QUERY_SIZE];
    uint8_t res_msg[HEADER_SIZE + RESPONSE_SIZE];
    struct header_t *req_header, *res_header;
    struct query_t *req_query;
    struct response_t *res_response;
    uint32_t res_id, res_passwd;

    fd_set rfds;
    struct timeval tv;
    unsigned int attempt;

    req_header = (struct header_t *)req_msg;
    req_query = (struct query_t *)(req_msg + HEADER_SIZE);
    res_header = (struct header_t *)res_msg;
    res_response = (struct response_t *)(res_msg + HEADER_SIZE);

    /* Build request message */
    req_header->magic = htonl(MAGIC);
    req_header->version = htons(VERSION);
    req_header->command = htons(REQUEST);
    req_query->id = htonl(id);
    req_query->passwd = htonl(guess);

    attempt = MAX_ATTEMPT;
    while (attempt > 0) {
        attempt--;
        send(sock, req_msg, sizeof(req_msg), 0);

        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);

        tv.tv_sec = TIMEOUT_SEC;
        tv.tv_usec = TIMEOUT_USEC;

        int retval = select(sock + 1, &rfds, NULL, NULL, &tv);
        switch (retval) {
        case -1:
            /* Error */
            PerrorAndExit("select");
        case 0:
            /* Timeout */
            break;
        default:
            recv(sock, res_msg, sizeof(res_msg), 0);

            if (!response_sanity_check(res_header, res_response, id, guess)) {
                attempt = MAX_ATTEMPT;
            } else {
                *result = (enum result_t)res_response->ret;
                return true;
            }
            break;
        }
    }

    return false;
}

bool response_sanity_check(const struct header_t *header,
                           const struct response_t *response,
                           const uint32_t id, const uint32_t guess) {
    bool correct = true;
    correct = correct && (ntohl(header->magic) == MAGIC);
    correct = correct && (ntohs(header->version) == VERSION);
    correct = correct && (ntohs(header->command) == RESPONSE);
    correct = correct && (ntohl(response->id) == id);
    correct = correct && (ntohl(response->passwd) == guess);
    return correct;
}

