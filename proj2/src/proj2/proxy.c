/*
 * proxy.c
 * 
 * EE324 Assignment 2
 * Part I   - sequential web proxy (implemented)
 * Part II  - concurrent web proxy (not implemented)
 * Part III - caching web objects (not implemented)
 *
 * Author: Lee, Byeoksan <lbs6170@kaist.ac.kr>
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "connection.h"
#include "definition.h"
#include "httpuri.h"
#include "listener.h"
#include "logger.h"
#include "thread_pool.h"

#define LOGFILE "proxy.log"

static int is_valid_method(const char *method);
static int is_valid_version(const char *version);
static void send_bad_request(struct connection *conn);

static int handle_connection(void *arg);

struct ptr_pair {
    void *first;
    void *second;
};

int main(int argc, char *argv[])
{
    int result;
    const char *port;
    long port_num;
    struct listener *listener = NULL;
    struct connection *conn_from_client = NULL;
    struct connection *conn_to_server = NULL;
    struct logger *logger = NULL;
    struct thread_pool *pool = NULL;
    struct sigaction action;

    if (argc < 2) {
        fprintf(stderr, "%s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    port = argv[1];
    port_num = strtol(port, NULL, 10);

    if (port_num < 1024 || port_num > 65535) {
        fprintf(stderr, "port number should be in range between 0 and 65535\n");
        exit(EXIT_FAILURE);
    }

    /* ignore SIGPIPE signal */
    action.sa_handler = SIG_IGN;
    sigemptyset(&action.sa_mask);
    sigaction(SIGPIPE, &action, NULL);

    pool = thread_pool_new(64);
    if (pool == NULL) {
        fprintf(stderr, "cannot create thread pool\n");
        goto fail;
    }

    logger = logger_new(LOGFILE);
    if (logger == NULL) {
        fprintf(stderr, "cannot create logger\n");
        goto fail;
    }

    listener = listener_new();
    if (listener == NULL) {
        fprintf(stderr, "Not enough memory\n");
        goto fail;
    }

    if (listener_open_and_bind(listener, port)) {
        fprintf(stderr, "failed to open or bind\n");
        goto fail;
    }

    if (listener_listen(listener)) {
        fprintf(stderr, "failed to listen\n");
        goto fail;
    }

    while ((conn_from_client = listener_accept(listener)) != NULL) {
        struct ptr_pair *pair = malloc(sizeof(*pair));
        if (pair == NULL) {
            fprintf(stderr, "no enough memory\n");
            connection_del(conn_from_client);
            thread_pool_stop(pool);
            goto fail;
        }

        pair->first = conn_from_client;
        pair->second = logger;
        thread_pool_add_work(pool, handle_connection, pair);
    }

    result = EXIT_SUCCESS;
    goto out;

fail:
    result = EXIT_FAILURE;
out:
    listener_del(listener);
    logger_del(logger);
    thread_pool_del(pool);
    exit(EXIT_SUCCESS);
}

static int is_valid_method(const char *method)
{
    int invalid = 1;
    invalid = strcmp(method, "OPTIONS") &&
              strcmp(method, "GET") &&
              strcmp(method, "HEAD") &&
              strcmp(method, "POST") &&
              strcmp(method, "PUT") &&
              strcmp(method, "DELETE") &&
              strcmp(method, "TRACE") &&
              strcmp(method, "CONNECT");

    return !invalid;
}

static int is_valid_version(const char *version)
{
    int invalid = 1;
    invalid = strcmp(version, "HTTP/1.0") &&
              strcmp(version, "HTTP/1.1");

    return !invalid;
}

static void send_bad_request(struct connection *conn)
{
    connection_send(conn, "HTTP/1.0 400 Bad Request" CRLF, 26);
}

static int handle_connection(void *arg)
{
    struct ptr_pair *pair = (struct ptr_pair *)arg;
    struct connection *conn_from_client, *conn_to_server;
    struct logger *logger;
    int s;
    ssize_t n;
    char method[16];
    char uri[512];
    char version[16];
    char line[512];
    uint32_t content_length;
    int host_header_found = 0;
    const char *header_end;
    size_t header_len;
    int do_not_forward;
    struct httpuri *httpuri = NULL;
    size_t response_size = 0;

    conn_from_client = pair->first;
    logger = pair->second;
    free(pair);

    /* method, uri and version */
    connection_readline(conn_from_client, line, sizeof(line));
    sscanf(line, "%s %s %s", method, uri, version);

    if (!is_valid_method(method)) {
        /* leave this for original server to handle it? */
        fprintf(stderr, "invalid method is given: %s\n", method);
        goto disconnect;
    }

    if (!is_valid_version(version)) {
        fprintf(stderr, "invalid version is given: %s\n", version);
        send_bad_request(conn_from_client);
        goto disconnect;
    }

    /* parse the uri */
    httpuri = httpuri_uri_to_httpuri(uri);
    if (httpuri == NULL) {
        fprintf(stderr, "uri is invalid or memory allocation fails\n");
        send_bad_request(conn_from_client);
        goto disconnect;
    }

    /* connect to original server */
    conn_to_server = connection_new();
    if (conn_to_server == NULL) {
        fprintf(stderr, "no enough memory\n");
        send_bad_request(conn_from_client);
        goto disconnect;
    }

    s = connection_connect(conn_to_server, httpuri_get_host(httpuri), httpuri_get_port(httpuri));
    if (s) {
        fprintf(stderr, "failed to connect to the original server\n");
        goto disconnect;
    }

    /* forward the start-line */
    /* we always send as HTTP/1.0 */
    n = snprintf(line, sizeof(line), "%s %s %s" CRLF, method, httpuri_get_abs_path(httpuri), "HTTP/1.0");
    if (n < 0) {
        fprintf(stderr, "failed to build start-line\n");
        goto disconnect;
    }
    connection_send(conn_to_server, line, n);

    /* forward the headers */
    content_length = 0;
    n = connection_readline(conn_from_client, line, sizeof(line));
    while (n > 2) {
        if (line[0] != SP && line[0] != HT) {
            /* new header field */
            do_not_forward = 0;
        }

        header_end = strchr(line, ':');
        if (header_end != NULL) {
            header_len = header_end - line;
            if (!strncasecmp(line, "host", header_len)) {
                host_header_found = 1;
            } else if (!strncasecmp(line, "content-length", header_len)) {
                content_length = strtoul(header_end + 1, NULL, 10);
            } else if (!strncasecmp(line, "connection", header_len)) {
                do_not_forward = 1;
            } else if (!strncasecmp(line, "keep-alive", header_len)) {
                do_not_forward = 1;
            }
        }

        if (!do_not_forward) {
            connection_send(conn_to_server, line, n);
        }

        n = connection_readline(conn_from_client, line, sizeof(line));
    }

    if (!host_header_found) {
        n = snprintf(line, sizeof(line), "Host: %s" CRLF, httpuri_get_host(httpuri));
        if (n < 0) {
            fprintf(stderr, "failed to build 'Host' header\n");
            goto disconnect;
        }
        connection_send(conn_to_server, line, n);
    }

    n = snprintf(line, sizeof(line), "Connection: close" CRLF);
    connection_send(conn_to_server, line, n);

    n = snprintf(line, sizeof(line), "Proxy-Connection: close" CRLF);
    connection_send(conn_to_server, line, n);

    connection_send(conn_to_server, CRLF, sizeof(CRLF) - 1);

    /* forward the body */
    size_t left = content_length;
    if (left > 0) {
        n = connection_recv(conn_from_client, line, sizeof(line));
        connection_send(conn_to_server, line, n);
        left -= n;
    }

    /* forward the response */
    n = connection_recv(conn_to_server, line, sizeof(line));
    response_size += n;
    while (n > 0) {
        connection_send(conn_from_client, line, n);
        n = connection_recv(conn_to_server, line, sizeof(line));
        response_size += n;
    }

    // logger_log(logger, conn_from_client, httpuri, response_size);
    printf("%s:%s%s done\n", httpuri_get_host(httpuri), httpuri_get_port(httpuri), httpuri_get_abs_path(httpuri));

disconnect:
    httpuri_del(httpuri);
    connection_del(conn_from_client);
    connection_del(conn_to_server);
    conn_from_client = NULL;
    conn_to_server = NULL;
    httpuri = NULL;
}
