#include <assert.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include "logger.h"

struct logger {
    char *filename;
    FILE *file;
};

static int logger_init(struct logger *logger, const char *filename);

struct logger *logger_new(const char *filename)
{
    assert(filename != NULL);
    struct logger *logger;
    logger = calloc(1, sizeof(*logger));
    if (!logger_init(logger, filename)) {
        return NULL;
    }

    return logger;
}

void logger_del(struct logger *logger)
{
    if (logger == NULL) {
        return;
    }

    fclose(logger->file);
    free(logger->filename);
    free(logger);
}

static int logger_init(struct logger *logger, const char *filename)
{
    assert(logger != NULL);
    assert(filename != NULL);

    logger->filename = strdup(filename);
    if (logger->filename == NULL) {
        return 0;
    }

    logger->file = fopen(logger->filename, "w");
    if (logger->file == NULL) {
        free(logger->filename);
        return 0;
    }

    return 1;
}

void logger_log(struct logger *logger, struct connection *conn, struct httpuri *httpuri, size_t size)
{
    assert(logger != NULL);
    assert(logger->file != NULL);
    assert(conn != NULL);
    assert(httpuri != NULL);

    time_t t;
    char time_str[64];
    char hostip[NI_MAXHOST];
    struct tm tm;
    int s;

    struct sockaddr_storage addr = {0};
    socklen_t addrlen;

    time(&t);
    localtime_r(&t, &tm);
    strftime(time_str, sizeof(time_str), "%a %d %b %G %T %Z", &tm);

    s = connection_getpeername(conn, (struct sockaddr *)&addr, &addrlen);
    if (s || addr.ss_family == AF_UNSPEC) {
        strcpy(hostip, "(unknown)");
    } else {
        s = getnameinfo((struct sockaddr *)&addr, addrlen, hostip, sizeof(hostip), NULL, 0, NI_NUMERICHOST);
        if (s) {
            strcpy(hostip, "(unknown)");
        }
    }

    fprintf(logger->file, "%s: %s http://%s%s %zd\n", time_str, hostip, httpuri_get_host(httpuri), httpuri_get_abs_path(httpuri), size);
    fflush(logger->file);
}

