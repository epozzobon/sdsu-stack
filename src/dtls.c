#include "webrtc_server.h"

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

BIO *make_dtls_socket(unsigned short port, int *sret) {
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

