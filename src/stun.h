#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <malloc.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

struct stun_transaction_id {
    char id[12];
};

struct stun_header {
    uint16_t msg_type;
    uint16_t msg_len;
    uint32_t magic_c;
    struct stun_transaction_id transaction;
};

struct stun_attribute_header {
    uint16_t attr_type;
    uint16_t attr_len;
};

struct hmac_sha1 {
    unsigned char hmac_sha1[20];
};

struct stun_complete_response {
    uint16_t msg_type;
    uint16_t msg_len;
    uint32_t magic_c;
    struct stun_transaction_id transaction;

    uint16_t attr_type0;
    uint16_t attr_len0;
    uint8_t reserved;
    uint8_t protocol_family;
    uint16_t x_port;
    uint32_t x_address;

    uint16_t attr_type1;
    uint16_t attr_len1;
    struct hmac_sha1 hmac_sha1;

    uint16_t attr_type2;
    uint16_t attr_len2;
    uint32_t crc;
};

int parse_stun(int s,
               const char *msg, size_t len,
               const struct stun_transaction_id **transaction,
               const char **username,
               const struct hmac_sha1 **msg_integrity
);

ssize_t stun_respond(int s, const struct sockaddr_in *addr,
                     const struct stun_transaction_id *transaction,
                     const char *key
);


unsigned long Crc32_ComputeBuf(unsigned long inCrc32,
                                      const void *buf,
                                      size_t bufLen);

struct hmac_sha1 compute_message_integriry(const char *key, const unsigned char *buf, size_t len);
