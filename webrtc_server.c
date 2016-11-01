#include "webrtc_server.h"

const int MTU = 1500;

long send_callback(BIO *wbio, int oper, const char *argp,
    int argi, long argl, long ret) {
  SN *sn;
  sn = (SN *) BIO_get_callback_arg(wbio);

  if (oper & BIO_CB_RETURN) {
    switch (oper) {
      case BIO_CB_RETURN | BIO_CB_FREE :
        break;

      case BIO_CB_RETURN | BIO_CB_READ :
        break;

      case BIO_CB_RETURN | BIO_CB_WRITE:
        if (BIO_ctrl_pending(wbio) > 0) {
          drain_wbio(wbio, sn);
        }

        debug("Written %ld bytes\n", ret);
        break;

      case BIO_CB_RETURN | BIO_CB_PUTS :
        break;

      case BIO_CB_RETURN | BIO_CB_GETS :
        break;

      case BIO_CB_RETURN | BIO_CB_CTRL :
        break;

      default:
        break;
    }

  }

  return ret;
}

int tun_alloc(const char *dev, uint8_t open_only)
{
  struct ifreq ifr;
  struct sockaddr_in *addr;
  int fd, err;

  if((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    perror("open /dev/net/tun");
    return fd;
  }

  fprintf(stderr, "Obtained fd %d\n", fd);
  memset(&ifr, 0, sizeof(ifr));

  // Select flags: tun device with no additional headers on packets
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

  // Set name for the tun device
  if( *dev )
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  // Actually request the tunnel
  if((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0){
    perror("ioctl TUNSETIFF");
    close(fd);
    return err;
  }

  // Set non blocking
  int saved_flags = fcntl(fd, F_GETFL);
  if ((err = fcntl(fd, F_SETFL, saved_flags | O_NONBLOCK)) < 0) {
    perror("fnctl non blocking tunnel");
    close(fd);
    return err;
  }

  if (open_only)
    return fd;

  // get a random socket cause why not
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("socket");
    close(fd);
    return -1;
  }

  // Set IP address
  addr = (struct sockaddr_in *) &ifr.ifr_addr;
  addr->sin_family = AF_INET;
  addr->sin_port = 0;
  inet_pton(AF_INET, "10.64.0.1", (struct in_addr *) &addr->sin_addr.s_addr);
  if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
    perror("failed to set ip address");
    close(sock);
    close(fd);
    return -1;
  }

  // Set Network mask
  addr = (struct sockaddr_in *) &ifr.ifr_netmask;
  addr->sin_family = AF_INET;
  addr->sin_port = 0;
  inet_pton(AF_INET, "255.240.0.0", (struct in_addr *) &addr->sin_addr.s_addr);
  if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
    perror("failed to set network mask");
    close(sock);
    close(fd);
    return -1;
  }

  // Set Broadcast Addr
  addr = (struct sockaddr_in *) &ifr.ifr_broadaddr;
  addr->sin_family = AF_INET;
  addr->sin_port = 0;
  inet_pton(AF_INET, "10.79.255.255", (struct in_addr *) &addr->sin_addr.s_addr);
  if (ioctl(sock, SIOCSIFBRDADDR, &ifr) < 0) {
    perror("failed to set broadcast address");
    close(sock);
    close(fd);
    return -1;
  }

  // Bring it UP!
  ifr.ifr_flags |= IFF_UP;
  if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
    perror("ifup");
    close(sock);
    close(fd);
    return -1;
  }

  debug("Successfully created tunnel\n");
  close(sock);

  return fd;
}

BIO *make_socket(unsigned short port, int *sret) {
  debug("SSL socket created\n");

  struct sockaddr_in client;
  client.sin_family = AF_INET;
  client.sin_port = htons(port);
  client.sin_addr.s_addr = htonl(INADDR_ANY);

  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) {
    perror("Unable to create socket");
    exit(EXIT_FAILURE);
  }

  if (bind(s, (struct sockaddr*)&client, sizeof(client)) < 0) {
    perror("Unable to bind");
    exit(EXIT_FAILURE);
  }

  int saved_flags = fcntl(s, F_GETFL);
  fcntl(s, F_SETFL, saved_flags | O_NONBLOCK);

  BIO *sbio;
  sbio = BIO_new_dgram(s, BIO_NOCLOSE);
  BIO_ctrl(sbio, BIO_CTRL_DGRAM_MTU_DISCOVER, 0, NULL);

  *sret = s;
  return sbio;
}

void tickle_sn(SN *sn) {
  SSL* ssl = sn->ssl;
  int len = 1;

  while (len > 0) {
    len = SSL_read(ssl, NULL, 0);
    int err = SSL_get_error(ssl, len);
    switch (err) {
      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE:
        break;
      case SSL_ERROR_ZERO_RETURN:
        sn->finish = 1;
        SSL_free(ssl);
        sn->ssl = NULL;
        break;
      case SSL_ERROR_SYSCALL:
        fprintf(stderr, "SSL_ERROR_SYSCALL %d\n", len);
        break;
      default:
        fprintf(stderr, "Error in SSL_read: %d\n", err);
        ERR_print_errors_fp(stderr);
    }
  }
}

uint16_t next_socket_node_id = 0;
SN* make_sn(struct state *state, char *username, char *password) {
  debug(">> SPAWNING NEW SSL SOCKET <<\n");

  SN* new_node;
  new_node = malloc(sizeof(*new_node));
  new_node->state = state;
  new_node->ass = NULL;

  SSL *con = SSL_new(state->ctx);
  if (!SSL_clear(con)) {
    fprintf(stderr, "Error clearing SSL connection\n");
    exit(EXIT_FAILURE);
  }
  SSL_set_options(con, SSL_OP_COOKIE_EXCHANGE);

  BIO *for_reading = BIO_new(BIO_s_mem());
  BIO *for_writing = BIO_new(BIO_s_mem());
  BIO_set_mem_eof_return(for_reading, -1);
  BIO_set_mem_eof_return(for_writing, -1);
  BIO_set_callback(for_writing, send_callback);
  BIO_set_callback_arg(for_writing, (char *) new_node);
  SSL_set_bio(con, for_reading, for_writing);

  SSL_set_accept_state(con);
  int fd = SSL_get_fd(con);
  int saved_flags = fcntl(fd, F_GETFL);
  fcntl(fd, F_SETFL, saved_flags | O_NONBLOCK);

  SSL_set_options(con, SSL_OP_COOKIE_EXCHANGE);
  con->d1->listen = 1;

  memset(&new_node->sockaddr, 0, sizeof(new_node->sockaddr));
  uint16_t id = next_socket_node_id++;
  new_node->tun_addr.s_addr = htonl(0x0a400002 + id);
  new_node->ssl = con;
  new_node->finish = 0;
  new_node->accepted = 0;
  new_node->username = username;
  new_node->password = password;
  debug("Created socket with tun_addr = %08x\n", htonl(new_node->tun_addr.s_addr));

  return new_node;
}

SN *accept_sn(const char *buf, int len, SN *sn) {
  BIO *rbio = SSL_get_rbio(sn->ssl);
  BIO_write(rbio, buf, len);

  int ret = SSL_accept(sn->ssl);
  if (ret > 0) {
    debug("Connection accepted successfully\n");
    sn->accepted = 1;
    return sn;
  } else {
    int err = SSL_get_error(sn->ssl, ret);
    switch (err) {
      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE:
        break;
      default:
        fprintf(stderr, "Error in SSL_accept: %d\n", err);
        ERR_print_errors_fp(stderr);
        if (ret == -1)
          perror("SSL_accept");
    }
    return NULL;
  }
}

void clean_sockets(struct state *state) {
  while (state->first != NULL && state->first->ssl == NULL) {
    SN* next = state->first->next;
    free(state->first);
    state->first = next;
  }
  for (SN* sn = state->first;
      sn != NULL && sn->next != NULL;
      sn = sn->next)
    while (sn->next != NULL && sn->next->ssl == NULL) {
      SN* next = sn->next->next;
      free(sn->next);
      sn->next = next;
    }
}

void tickle_all(struct state *state) {
  int dirty = 0;
  for (SN* sn = state->first; sn != NULL; sn = sn->next) {
    if (sn->ssl != NULL)
      tickle_sn(sn);

    if (sn->ssl == NULL)
      dirty = 1;
  }

  if (dirty)
    clean_sockets(state);
}

uint16_t in_cksum(uint16_t *addr, int len)
{
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

int send_ip(int tun, const char *buf, ssize_t read_ret,
    uint8_t protocol, struct in_addr src, struct in_addr dst) {
  char pkt[MTU];

  struct ipv4_hdr *pkt_hdr = (struct ipv4_hdr *)(pkt);
  const int max = MTU - sizeof(*pkt_hdr);
  int len = read_ret > max ? max : read_ret;
  pkt_hdr->version_ihl = 0x45;
  pkt_hdr->type_of_service = 0;
  pkt_hdr->total_length = htons(len + sizeof(*pkt_hdr));
  pkt_hdr->identification = htons(0);
  pkt_hdr->flags_fragment_offset = htons(0x4000);
  pkt_hdr->time_to_live = 64;
  pkt_hdr->protocol = protocol;
  pkt_hdr->header_checksum = htons(0);
  pkt_hdr->source_address = (uint32_t) src.s_addr;
  pkt_hdr->destination_address = (uint32_t) dst.s_addr;
  uint16_t chksum = in_cksum((uint16_t *)pkt_hdr, sizeof(*pkt_hdr));
  pkt_hdr->header_checksum = chksum;
  memcpy(pkt + sizeof(*pkt_hdr), buf, max);
  debug("sending %dB to 0x%08x over IP\n", read_ret, htonl(dst.s_addr));
  return write(tun, pkt, len + sizeof(*pkt_hdr));
}

unsigned int endpoints_router(struct state *state) {
  const int MAX_BUFFER = 1024*16;
  char buf[MAX_BUFFER];
  char pkt[MTU];
  unsigned int result = 0;

  while (1) {

    struct sockaddr_in frombuf;
    struct sockaddr *from = (struct sockaddr *) &frombuf;
    socklen_t fromlen = sizeof(frombuf);
    int received = (int) recvfrom(state->s, buf, MAX_BUFFER, MSG_DONTWAIT, from, &fromlen);

    if (received <= 0)
      break;

    const char *username;
    const struct hmac_sha1 *msg_integrity;
    const struct stun_transaction_id *transaction;
    int ret = parse_stun(state->s, buf, (size_t) received, &transaction, &username, &msg_integrity);

    if (ret > 0) {

      if (username != NULL && msg_integrity != NULL) {
        uint16_t username_length = htons(*(((uint16_t *) username) - 1));
        int colon_idx;
        for (colon_idx = 0; colon_idx < username_length && username[colon_idx] != ':'; colon_idx++);
        if (colon_idx < username_length) {
          buf[username - buf + colon_idx] = 0;

          SN *sn = getSnFromUsername(state, username);
          if (sn != NULL) {
            const char *password = sn->password;

            // TODO: Verify message integrity

            sn->sockaddr = frombuf;
            stun_respond(state->s, &frombuf, transaction, password);
          }
        }
      }

    } else {

      SN *sn = getSnFromSockaddr(state, &frombuf);
      if (sn != NULL) {
        if (sn->accepted) {
          BIO *rbio = SSL_get_rbio(sn->ssl);
          BIO_write(rbio, buf, received);
          received = 0;

          int read_ret;
          if ((read_ret = get_from_SSL(sn, buf, MAX_BUFFER)) > 0) {

            debug("Sending %dB packet to tunnel\n", read_ret);
            if (state->tun > 0) {
              struct in_addr src, dst;
              src.s_addr = sn->tun_addr.s_addr;
              dst.s_addr = htonl(0x0a400001);
              send_ip(state->tun, buf, read_ret, 132, src, dst);
            }

            int res = sctp_received_cb(sn, buf, read_ret);
            debug("sctp_received_cb returned %d\n", res);

          }
        } else {
          accept_sn(buf, received, sn);
        }
      }

    }

  }

  return result;
}

SN *getSnFromSockaddr(const struct state *state, const struct sockaddr_in *frombuf) {
  SN *sn;
  for (sn = state->first; sn != NULL; sn = sn->next) {

    if (memcmp(&(*frombuf).sin_addr, &sn->sockaddr.sin_addr, sizeof(struct in_addr)) == 0 &&
        (*frombuf).sin_port == sn->sockaddr.sin_port) {

      return sn;
    }
  }
  return NULL;
}

SN *getSnFromTunAddr(const struct state *state, struct in_addr tun_addr) {
  SN *sn;
  for (sn = state->first; sn != NULL; sn = sn->next) {
    if (sn->tun_addr.s_addr == tun_addr.s_addr) {
      return sn;
    }
  }
  return NULL;
}

SN *getSnFromUsername(const struct state *state, const char *username) {
  SN *sn;
  for (sn = state->first; sn != NULL; sn = sn->next) {
    if (strcmp(username, sn->username) == 0) {
      return sn;
    }
  }
  return NULL;
}

unsigned int tun_router(struct state *state) {
  char pkt[MTU];
  unsigned int result = 0;
  struct ipv4_hdr *pkt_hdr = (struct ipv4_hdr *) pkt;

  if (state->tun < 0)
    return 0;

  while (1) {

    ssize_t ret = read(state->tun, pkt, MTU);
    if (ret <= 0)
      break;

    if (ret < 20) {
      debug("Read %d bytes from tun\n", ret);
      continue;
    }
    if ((pkt[0] & 0xf0) != 0x40) {
      debug("Packet is not IP: %d\n", pkt[0]);
      continue;
    }
    int hdr_len = (pkt[0] & 0x0f) * 4;
    char *payload = pkt + hdr_len;
    ssize_t payload_len = ret - hdr_len;

    struct in_addr tun_addr;
    tun_addr.s_addr = pkt_hdr->destination_address;

    if (pkt_hdr->protocol == 17 && payload_len >= sizeof(struct udp_hdr)) {
      struct udp_hdr *udp = (void *) payload;
      payload += sizeof(*udp);
      payload_len -= sizeof(*udp);

      if (htons(udp->destination_port) == 39573) {
        debug("API packet\n");
        api_command(state, payload, payload_len);
      } else if (htons(udp->destination_port) == 5000) {
        SN *sn = getSnFromTunAddr(state, tun_addr);
        if (sn == NULL) {
          debug("Destination %08x is unknown\n", htonl(tun_addr.s_addr));
          continue;
        }
        
        sctp_send(sn, payload, payload_len);

      } else {
        debug("Ignored UDP packet for port %d\n", udp->destination_port);
        continue;
      }
    } else if (pkt_hdr->protocol != 132) {
      debug("Packet is not SCTP: %d\n", pkt_hdr->protocol);
      continue;
    }

    SN *sn = getSnFromTunAddr(state, tun_addr);
    if (sn == NULL) {
      debug("Destination %08x is unknown\n", htonl(tun_addr.s_addr));
      continue;
    }

    /*
    debug("Got %d bytes of SCTP data from tun, sending to SSL.\n", ret - hdr_len);
    SSL_write(sn->ssl, payload, ret - hdr_len);
    */

    result++;
  }

  return result;
}

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

int send_udp(int tun, const char *buf, ssize_t len,
    struct in_addr src, struct in_addr dst,
    uint16_t src_port, uint16_t dst_port) {

  char pkt_buf[MTU - sizeof(struct ipv4_hdr) + sizeof(struct ipv4_phdr)];
  char *pkt = pkt_buf + sizeof(struct ipv4_phdr);
  char *payload = pkt + sizeof(struct udp_hdr);

  struct ipv4_phdr *pip = (void *) pkt_buf;
  struct udp_hdr *udp = (void *) pkt;

  uint16_t complete_length = len + sizeof(struct udp_hdr);
  if (complete_length > MTU - sizeof(struct ipv4_hdr)) {
    fprintf(stderr, "send_udp error: out of bounds\n");
    exit(EXIT_FAILURE);
  }

  pip->protocol = 17;
  pip->zeroes = 0;
  pip->udp_length = htons(complete_length);
  pip->source_address = (uint32_t) src.s_addr;
  pip->destination_address = (uint32_t) dst.s_addr;

  udp->source_port = src_port;
  udp->destination_port = dst_port;
  udp->length = htons(complete_length);
  udp->checksum = htons(0);
  memcpy(payload, buf, len);

  uint16_t chksum = in_cksum((uint16_t *)pip, sizeof(struct ipv4_phdr) + complete_length);
  udp->checksum = chksum;

  debug("sending %dB to 0x%08x over UDP\n", len, htonl(dst.s_addr));
  return send_ip(tun, pkt, complete_length, 17, src, dst);
}

void api_send(struct state *state, const char *buf, ssize_t len) {
  struct in_addr src, dst;
  src.s_addr = htonl(0x0a4ffffe);
  dst.s_addr = htonl(0x0a400001);
  send_udp(state->tun, buf, len, src, dst, htons(39573), htons(39573));
}

unsigned int api_command(struct state *state, const char *api_msg, ssize_t msg_len) {
  unsigned int result = 0;
  if (msg_len <= 0) {
    fprintf(stderr, "Received API message with length %d\n", msg_len);
    exit(EXIT_FAILURE);
  }

  char messageType = api_msg[0];
  api_msg++;

  debug("Message from API, type %d, length %d\n", messageType, msg_len);

  switch (messageType) {

    case 1:
      { // CREATE

        int usernameLength;
        buffer_read(&usernameLength, sizeof(usernameLength), &api_msg, &msg_len);
        char *username = malloc((size_t) usernameLength + 1);
        buffer_read(username, (size_t) usernameLength, &api_msg, &msg_len);
        username[usernameLength] = 0;

        int passwordLength;
        buffer_read(&passwordLength, sizeof(passwordLength), &api_msg, &msg_len);
        char *password = malloc((size_t) passwordLength + 1);
        buffer_read(password, (size_t) passwordLength, &api_msg, &msg_len);
        password[passwordLength] = 0;

        debug("user received: %s, password: %s\n", username, password);
        SN *sn = make_sn(state, username, password);
        sn->next = state->first;
        state->first = sn;

        uint32_t user_endpoint = sn->tun_addr.s_addr;

        char resp_buf[100];
        char *resp = resp_buf;
        ssize_t remaining = 100;
        buffer_write(&resp, &remaining, &"\1", 1);
        buffer_write(&resp, &remaining, &usernameLength, sizeof(usernameLength));
        buffer_write(&resp, &remaining, username, usernameLength);
        buffer_write(&resp, &remaining, &user_endpoint, sizeof(user_endpoint));

        api_send(state, resp_buf, 100 - remaining);

      } break;

    default:
      {
        fprintf(stderr, "Unknown API message type: %d\n", messageType);
      }


  }

  return result;
}

void assert_read(int socket, void *buf, size_t len) {
  ssize_t ret = read(socket, buf, len);
  if (ret != len) {
    fprintf(stderr, "Couldn't read %d bytes from api socket.", (int) len);
    exit(EXIT_FAILURE);
  }
}

int get_from_SSL(SN *sn, char *buf, int MAX_BUFFER) {
  int read_ret = SSL_read(sn->ssl, buf, MAX_BUFFER);
  if (read_ret <= 0) {
    SSL *ssl = sn->ssl;
    int err = SSL_get_error(ssl, read_ret);
    switch (err) {
      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE:
        break;
      case SSL_ERROR_ZERO_RETURN:
        sn->finish = 1;
        SSL_free(ssl);
        sn->ssl = NULL;
        break;
      default:
        fprintf(stderr, "Error in SSL_read %d\n", err);
        ERR_print_errors_fp(stderr);
        if (read_ret == -1)
          perror("DTLSv1_listen");
    }
  }
  return read_ret;
}

int wait_msg(const struct state *state) {
  fd_set readset;
  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  FD_ZERO(&readset);
  FD_SET(state->s, &readset);
  FD_SET(state->tun, &readset);
  return select(state->s + 1, &readset, NULL, NULL, &tv);
}

int main(int argc, char **argv) {
  unsigned short port = 10000;
  struct state *state;
  state = malloc(sizeof(*state));
  state->first = NULL;
  state->tun = tun_alloc("tun_dondola", 1);
  if (state->tun < 0) {
    perror("tun failed");
    return 1;
  }

  debug("Creating socket...\n");
  make_socket(port, &state->s);
  debug("Initializing SSL...\n");
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
  debug("Creating context...\n");
  state->ctx = create_context();
  configure_context(state->ctx);
  sctp_init(state);

  while (state) {
    if (wait_msg(state) > 0) {
      endpoints_router(state);
      tun_router(state);
    }
    tickle_all(state);
  }

  SSL_CTX_free(state->ctx);
  EVP_cleanup();
}

int debug(const char *format, ...) {
#ifdef DEBUG
  va_list argptr;
  va_start(argptr, format);
  int r = vfprintf(stderr, format, argptr);
  va_end(argptr);
  return r;
#else
  return 0;
#endif //DEBUG
}
