/*
 * Copyright 2015 Lee, Byeoksan
 */
#ifndef PROJ1_GUESS_PASSWORD_H_
#define PROJ1_GUESS_PASSWORD_H_

#include <cstdint>

#include <proj1/msg.h>

void Usage();
void PerrorAndExit(const char *msg);
int GetConnectedSocketOrExit(const char *host, const char *port);
bool GuessOnce(const int sock, const uint32_t id,
               const uint32_t guess, enum result_t *result);
bool response_sanity_check(const struct header_t *header,
                           const struct response_t *response,
                           const uint32_t id, const uint32_t guess);

#endif  // PROJ1_GUESS_PASSWORD_H_

