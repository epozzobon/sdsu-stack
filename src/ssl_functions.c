#include "webrtc_server.h"

SSL_CTX *create_context() {
  const SSL_METHOD *method;
  SSL_CTX *ctx;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L // OpenSSL 1.1.0
  method = DTLS_server_method();
#else
  method = DTLSv1_2_server_method();
#endif

  ctx = SSL_CTX_new(method);
  if (!ctx) {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  return ctx;
}

int generate_cookie_callback(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
  if (*cookie_len > 16)
    *cookie_len = 16;
  memset(cookie, 0, *cookie_len);
  return 1; // TODO generate the cookie
}

int verify_cookie_callback(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
  return 1; // TODO verify the cookie
}

void configure_context(SSL_CTX *ctx) {
  SSL_CTX_set_ecdh_auto(ctx, 1);

  /* Set the key and cert */
  if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) != 1) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) != 1) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie_callback);
  SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie_callback);
}

void drain_wbio(BIO *wbio, SN *sn) {
  const int MAX_BUFFER = 1024*16;
  char buf[MAX_BUFFER];

  int outsize = BIO_read(wbio, buf, MAX_BUFFER);
  size_t len = (size_t) outsize;
  const struct sockaddr *dest_addr;
  dest_addr = (const struct sockaddr *) &sn->sockaddr;
  socklen_t addrlen = sizeof(sn->sockaddr);
  ssize_t rc2 = sendto(sn->state->s, buf, len, 0, dest_addr, addrlen);
  if (rc2 == -1) {
    perror("sendto");
  }
}
