#include <assert.h>
#include <stdlib.h>

#include "httpuri.h"

struct httpuri {
    char *host;
    char *abs_path;
    char *port;
};

static void httpuri_init(struct httpuri *httpuri);

struct httpuri *httpuri_new(void)
{
    struct httpuri *httpuri;
    httpuri = calloc(1, sizeof(*httpuri));

    if (httpuri != NULL) {
        httpuri_init(httpuri);
    }

    return httpuri;
}

void httpuri_del(struct httpuri *httpuri)
{
    if (httpuri == NULL) {
        return;
    }

    free(httpuri->host);
    free(httpuri->abs_path);
    free(httpuri->port);
    free(httpuri);
}

static void httpuri_init(struct httpuri *httpuri)
{
    assert(httpuri != NULL);
    httpuri->host = NULL;
    httpuri->abs_path = NULL;
    httpuri->port = NULL;
}

struct httpuri *httpuri_uri_to_httpuri(const char *uri)
{
    size_t uri_len;
    const char *host, *host_end;
    const char *abs_path;
    const char *port;

    size_t host_len;
    size_t abs_path_len;
    size_t port_len;

    struct httpuri *httpuri;

    if (uri == NULL) {
        return NULL;
    }

    if (strncasecmp(uri, HTTP_SCHEME, sizeof(HTTP_SCHEME)-1)) {
        return NULL;
    }

    httpuri = httpuri_new();
    if (httpuri == NULL) {
        return NULL;
    }

    /* uri without the scheme */
    uri = uri + sizeof(HTTP_SCHEME) - 1;
    uri_len = strlen(uri);

    host = uri;
    abs_path = strchr(uri, '/');
    port = strchr(uri, ':');

    if (abs_path == NULL) {
        abs_path = uri + uri_len;
    }

    if (port != NULL && port > abs_path) {
        port = NULL;
    }

    host_end = (port == NULL) ? abs_path : port;
    port = (port == NULL) ? DEFAULT_PORT : port + 1;
    if (*abs_path == '\0') {
        abs_path = DEFAULT_ABS_PATH;
    }

    host_len = host_end - host;
    abs_path_len = strlen(abs_path);
    if (port == DEFAULT_PORT) {
        port_len = sizeof(DEFAULT_PORT) - 1;
    } else {
        port_len = abs_path - port;
    }

    /* any absence? */
    if (host_len == 0 || abs_path_len == 0 || port_len == 0) {
        goto fail;
    }

    /* copy those */
    httpuri->host = malloc(host_len + 1);
    if (httpuri->host == NULL) {
        goto fail;
    }

    httpuri->abs_path = malloc(abs_path_len + 1);
    if (httpuri->abs_path == NULL) {
        goto fail;
    }

    httpuri->port = malloc(port_len + 1);
    if (httpuri->port == NULL) {
        goto fail;
    }

    memcpy(httpuri->host, host, host_len);
    memcpy(httpuri->abs_path, abs_path, abs_path_len);
    memcpy(httpuri->port, port, port_len);
    httpuri->host[host_len] = '\0';
    httpuri->abs_path[abs_path_len] = '\0';
    httpuri->port[port_len] = '\0';

    return httpuri;

fail:
    httpuri_del(httpuri);
    return NULL;
}

const char *httpuri_get_host(struct httpuri *httpuri)
{
    assert(httpuri != NULL);
    return httpuri->host;
}

const char *httpuri_get_port(struct httpuri *httpuri)
{
    assert(httpuri != NULL);
    return httpuri->port;
}

const char *httpuri_get_abs_path(struct httpuri *httpuri)
{
    assert(httpuri != NULL);
    return httpuri->abs_path;
}
