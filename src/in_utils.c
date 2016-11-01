#include "webrtc_server.h"

void buffer_read(void *dst, size_t dst_len, const char **src, ssize_t *src_len) {
  if (*src_len < dst_len) {
    fprintf(stderr, "Not enough data to read: wanted %d, got %d\n", dst_len, *src_len);
    exit(EXIT_FAILURE);
  }

  memcpy(dst, *src, dst_len);

  *src_len -= dst_len;
  *src += dst_len;
}

void buffer_write(char **dst, size_t *dst_len, const void *src, ssize_t src_len) {
  if (*dst_len < src_len) {
    fprintf(stderr, "Not enough data to write: wanted %d, got %d\n", src_len, *dst_len);
    exit(EXIT_FAILURE);
  }

  memcpy(*dst, src, src_len);

  *dst_len -= src_len;
  *dst += src_len;
}

void assert_read(int socket, void *buf, size_t len) {
  ssize_t ret = read(socket, buf, len);
  if (ret != len) {
    fprintf(stderr, "Couldn't read %d bytes from api socket.", (int) len);
    exit(EXIT_FAILURE);
  }
}

uint16_t in_cksum(uint16_t *addr, int len) {
  register int nleft = len;
  register uint16_t *w = addr;
  register int sum = 0;
  uint16_t answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)  {
    sum += *w++;
    nleft -= 2;
  }

  /* mop up an odd byte, if necessary */
  if (nleft == 1) {
    *(uint8_t *)(&answer) = *(uint8_t *)w ;
    sum += answer;
  }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
  sum += (sum >> 16);         /* add carry */
  answer = ~sum;              /* truncate to 16 bits */
  return(answer);
}

uint32_t crc32c(uint32_t c, const uint8_t *buffer,
                   unsigned int length) {
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

