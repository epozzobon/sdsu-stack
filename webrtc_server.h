#pragma once

#include <stdio.h>
#include <memory.h>
#include <malloc.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "stun.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#define DEBUG

struct socket_node {
    struct socket_node* next;
    struct state *state;
    struct sctp_association *ass;
    char *username;
    char *password;
    SSL* ssl;
    struct sockaddr_in sockaddr;
    struct in_addr tun_addr;
    uint8_t finish;
    uint8_t accepted;
};
typedef struct socket_node SN;

struct state {
    struct socket_node* first;
    int s;
    SSL_CTX *ctx;
    int tun;
};

struct sctp_association {
    uint32_t init_tag;
    uint32_t rcv_tsn;
    uint32_t snd_tsn;
    uint8_t ack_required;
};

struct ipv4_hdr {
    uint8_t version_ihl;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t source_address;
    uint32_t destination_address;
};

struct ipv4_phdr {
    uint32_t source_address;
    uint32_t destination_address;
    uint8_t zeroes;
    uint8_t protocol;
    uint16_t udp_length;
};

struct udp_hdr {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
};

struct sctp_comm_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t verification;
    uint32_t checksum;
};

struct sctp_varlen_par {
    uint16_t type;
    uint16_t length;
};

struct sctp_chunk_hdr {
    uint8_t type;
    uint8_t flags;
    uint16_t length;
};

struct sctp_DATA {
    uint8_t type;
    uint8_t flags;
    uint16_t length;
    uint32_t tsn;
    uint16_t sid;
    uint16_t ssn;
    uint32_t ppid;
};

struct sctp_INIT {
    uint8_t type;
    uint8_t flags;
    uint16_t length;
    uint32_t init_tag;
    uint32_t a_rwnd;
    uint16_t noos;
    uint16_t nois;
    uint32_t init_tsn;
};

struct sctp_SACK {
    uint8_t type;
    uint8_t flags;
    uint16_t length;
    uint32_t tsn;
    uint32_t a_rwnd;
    uint16_t nogb;
    uint16_t nodt;
};

struct sctp_HEARTBEAT {
    uint8_t type;
    uint8_t flags;
    uint16_t length;
    uint16_t info_type;
    uint16_t info_len;
};

struct sctp_FORWARD_TSN {
    uint8_t type;
    uint8_t flags;
    uint16_t length;
    uint32_t tsn;
};

#define sctp_INIT_ACK sctp_INIT
#define sctp_COOKIE_ECHO sctp_chunk_hdr
#define sctp_COOKIE_ACK sctp_chunk_hdr
#define sctp_HEARTBEAT_ACK sctp_HEARTBEAT

int send_ip(int tun, const char *buf, ssize_t read_ret,
    uint8_t protocol, struct in_addr src, struct in_addr dst);

int send_udp(int tun, const char *buf, ssize_t len,
    struct in_addr src, struct in_addr dst,
    uint16_t src_port, uint16_t dst_port);

int tun_alloc(const char *dev, uint8_t open_only);

SSL_CTX *create_context();

SN *getSnFromSockaddr(const struct state *state, const struct sockaddr_in *frombuf);

SN *getSnFromTunAddr(const struct state *state, struct in_addr tun_addr);

SN *getSnFromUsername(const struct state *state, const char *username);

int generate_cookie_callback(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len);

int verify_cookie_callback(SSL *ssl, unsigned char *cookie, unsigned int cookie_len);

void configure_context(SSL_CTX *ctx);

int sctp_init(struct state *);

int sctp_received_cb(SN *sn, char *buf, size_t len);

int sctp_send(SN *sn, char *buf, size_t len);

/**
 * Reads a packet from wbio and sends it to the UDP address sn->sockaddr
 */
void drain_wbio(BIO *wbio, SN *sn);

int get_from_SSL(SN *sn, char *buf, int MAX_BUFFER);

long send_callback(BIO *wbio, int oper, const char *argp,
                   int argi, long argl, long ret);

BIO *make_socket(unsigned short port, int *sret);

void tickle_sn(SN *sn);

SN *make_sn(struct state *state, char *username, char *password);

void clean_sockets(struct state *state);

void tickle_all(struct state *state);

unsigned int endpoints_router(struct state *state);

unsigned int api_command(struct state *state, const char *api_msg, ssize_t msg_len);

int wait_msg(const struct state *state);

int open_api_socket();

int main(int argc, char **argv);

SN * accept_new_sn(struct state *state, struct sockaddr_in *addr, char buf[], int len);

extern int debug(const char *__restrict __format, ...);

void buffer_read(void *dst_buf, size_t dst_len, const char **src, ssize_t *src_len);

static const uint32_t sctp_crc_c[256] = {
	0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4,
	0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,
	0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B,
	0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,
	0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B,
	0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,
	0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54,
	0x5D1D08BF, 0xAF768BBC, 0xBC267848, 0x4E4DFB4B,
	0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A,
	0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35,
	0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5,
	0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,
	0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45,
	0xF779DEAE, 0x05125DAD, 0x1642AE59, 0xE4292D5A,
	0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A,
	0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595,
	0x417B1DBC, 0xB3109EBF, 0xA0406D4B, 0x522BEE48,
	0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,
	0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687,
	0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198,
	0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927,
	0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38,
	0xDBFC821C, 0x2997011F, 0x3AC7F2EB, 0xC8AC71E8,
	0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
	0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096,
	0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789,
	0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859,
	0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46,
	0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9,
	0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
	0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36,
	0x3CDB9BDD, 0xCEB018DE, 0xDDE0EB2A, 0x2F8B6829,
	0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C,
	0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93,
	0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043,
	0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,
	0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3,
	0x55326B08, 0xA759E80B, 0xB4091BFF, 0x466298FC,
	0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C,
	0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033,
	0xA24BB5A6, 0x502036A5, 0x4370C551, 0xB11B4652,
	0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D,
	0x2892ED69, 0xDAF96E6A, 0xC9A99D9E, 0x3BC21E9D,
	0xEF087A76, 0x1D63F975, 0x0E330A81, 0xFC588982,
	0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D,
	0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622,
	0x38CC2A06, 0xCAA7A905, 0xD9F75AF1, 0x2B9CD9F2,
	0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED,
	0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530,
	0x0417B1DB, 0xF67C32D8, 0xE52CC12C, 0x1747422F,
	0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF,
	0x8ECEE914, 0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0,
	0xD3D3E1AB, 0x21B862A8, 0x32E8915C, 0xC083125F,
	0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
	0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90,
	0x9E902E7B, 0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F,
	0xE330A81A, 0x115B2B19, 0x020BD8ED, 0xF0605BEE,
	0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1,
	0x69E9F0D5, 0x9B8273D6, 0x88D28022, 0x7AB90321,
	0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,
	0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81,
	0x34F4F86A, 0xC69F7B69, 0xD5CF889D, 0x27A40B9E,
	0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E,
	0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351,
};

static uint32_t crc32c(uint32_t c,
                   const uint8_t *buffer,
                   unsigned int length)
{
	unsigned int i;

  c = ~c;
	for (i = 0; i < length; i++) {
    uint8_t d = buffer[i];
    uint8_t idx = (c ^ d) & 0xFF;
    uint32_t chd = sctp_crc_c[idx];
    c = (c >> 8) ^ chd;
	}
	return ~c;
}
