#include "webrtc_server.h"

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
#if OPENSSL_VERSION_NUMBER < 0x10100000L // OpenSSL 1.1.0
  con->d1->listen = 1;
#endif

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
	//debug("Getting SN from addr %lx...\n", htonl(tun_addr.s_addr));
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
  make_dtls_socket(port, &state->s);
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
