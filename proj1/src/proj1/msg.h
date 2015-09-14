#pragma once
#ifndef __MSGH__
#define __MSGH__

#pragma pack(push, 1)

#define MAGIC 0x323324
#define VERSION 1

enum command_t {
    REQUEST = 0,
    RESPONSE,
    REGISTER
};

enum result_t {
    USER_NOT_REGISTERED= 0,
    LT,  /* Real password < guessed password */
    EQ,  /* Real password == guessed password */
    GT  /* Real password > guessed password */
};

struct header_t {
    uint32_t magic;
    uint16_t version;
    uint16_t command;
};

struct query_t {
    uint32_t id;
    uint32_t passwd;
};

struct response_t {
    uint32_t id;
    uint32_t passwd;
    char ret;
};

#pragma pack(pop)
#endif
