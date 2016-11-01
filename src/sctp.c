#include "webrtc_server.h"

int sctp_init(struct state *state) {
  return 0;
}

int sctp_internal_send(SN *sn, struct sctp_comm_hdr *resp_hdr, size_t resp_len) {
  void *resp = resp_hdr;
  resp_hdr->checksum = 0;
  resp_hdr->checksum = crc32c(0, resp, resp_len);

  // To SSL
  SSL_write(sn->ssl, resp, resp_len);

  // To tunnel too, for wireshark
  struct in_addr src, dst;
  dst.s_addr = sn->tun_addr.s_addr;
  src.s_addr = htonl(0x0a400001);
  return send_ip(sn->state->tun, resp, resp_len, 132, src, dst);
}

int sctp_received_DATA(SN *sn, struct sctp_DATA *ch) {
  uint32_t rcv_tsn = htonl(ch->tsn);
  if (rcv_tsn >= sn->ass->rcv_tsn) {
    sn->ass->ack_required = 1;
    sn->ass->rcv_tsn = rcv_tsn;
  }

  struct in_addr src, dst;
  src.s_addr = sn->tun_addr.s_addr;
  dst.s_addr = htonl(0x0a400001);
  char *buf = (void *) ch + sizeof(*ch);
  size_t data_len = htons(ch->length) - sizeof(*ch);
  int rr = send_udp(sn->state->tun, buf, data_len, src, dst, htons(5000), htons(5000));

  /*if (sn->ass->ack_required) {
    sn->ass->ack_required = 0;

    char resp[sizeof(struct sctp_comm_hdr) + sizeof(struct sctp_SACK)];
    struct sctp_comm_hdr *resp_hdr = (void *) resp;
    struct sctp_SACK *rch = (void *) (resp + sizeof(*resp_hdr));

    resp_hdr->src_port = htons(5000);
    resp_hdr->dst_port = htons(5000);
    resp_hdr->verification = sn->ass->init_tag;

    rch->length = htons(16);
    rch->type = 3;
    rch->flags = 0;
    rch->tsn = htonl(sn->ass->rcv_tsn);
    rch->a_rwnd = htonl(0x20000);
    rch->nogb = 0;
    rch->nodt = 0;

    return sctp_internal_send(sn, resp_hdr, sizeof(*resp_hdr) + htons(rch->length));
  }*/

  return 0;
}

int sctp_received_INIT(SN *sn, struct sctp_INIT *ch) {
  if (sn->ass != NULL) {
    if (sn->ass->init_tag == ch->init_tag)
      return 0;

    debug("Socket node was already associated\n");
    return -1;
  }

  sn->ass = malloc(sizeof(*sn->ass));
  sn->ass->init_tag = ch->init_tag;
  sn->ass->ack_required = 0;
  debug("Beginning association %u\n", htonl(ch->init_tag));

  sn->ass->rcv_tsn = htonl(ch->init_tsn);
  sn->ass->snd_tsn = htonl(ch->init_tag);

  const size_t COOKIE_LEN = 8;
  const size_t TOTAL_VAR_LEN = 8 + COOKIE_LEN;
  const size_t resp_len = sizeof(struct sctp_comm_hdr) +
    sizeof(struct sctp_INIT_ACK) + TOTAL_VAR_LEN;
  char resp[resp_len];
  struct sctp_comm_hdr *resp_hdr = (void *) resp;
  struct sctp_INIT_ACK *rch = (void *) (resp + sizeof(*resp_hdr));
  void *off = (void *) rch + sizeof(*rch);
  struct sctp_varlen_par *res_state_cookie = off; off += 4; off += COOKIE_LEN;
  struct sctp_varlen_par *res_unrel_stream = off; off += 4;
  struct sctp_varlen_par *res_support_exts = off; off += 4;
  char *res_support_exts_data = off; off += 1;
  uint16_t rch_len = off - (void *) rch;

  resp_hdr->src_port = htons(5000);
  resp_hdr->dst_port = htons(5000);
  resp_hdr->verification = ch->init_tag;

  rch->type = 2;
  rch->flags = 0;
  rch->length = htons(rch_len);
  rch->init_tag = ch->init_tag;
  rch->a_rwnd = ch->a_rwnd;
  rch->noos = ch->noos;
  rch->nois = ch->nois;
  rch->init_tsn = ch->init_tag;

  res_state_cookie->type = htons(7);
  res_state_cookie->length = htons(4 + COOKIE_LEN);

  res_unrel_stream->type = htons(0xC000);
  res_unrel_stream->length = htons(4);

  res_support_exts->type = htons(0x8008);
  res_support_exts->length = htons(5);
  res_support_exts_data[0] = 192;

  return sctp_internal_send(sn, resp_hdr, rch_len + sizeof(*resp_hdr));
}

int sctp_received_SACK(SN *sn, struct sctp_SACK *ch) {/*
  uint16_t nogb = htons(ch->nogb);
  uint32_t tsn = htonl(ch->tsn);

  if (nogb != 0) {
    //TODO: check length of input
    printf("There are %u Gap Ack Blocks\n", nogb);

    char resp[sizeof(struct sctp_comm_hdr) + htons(ch->length)];
    struct sctp_comm_hdr *resp_hdr = (void *) resp;
    void *offset = resp + sizeof(*resp_hdr);

    resp_hdr->src_port = htons(5000);
    resp_hdr->dst_port = htons(5000);
    resp_hdr->verification = sn->ass->init_tag;

    uint16_t *gaps = (void *) ch + sizeof(*ch);
    int i = 0;
    for (int i = nogb-1; i < nogb; i++) {
      struct sctp_FORWARD_TSN *fch = offset;

      uint32_t gap_start = tsn + htons(gaps[i*2]);
      uint32_t gap_end = tsn + htons(gaps[i*2 + 1]);
      fch->type = 0xC0;
      fch->flags = 0;
      fch->length = htons(sizeof(*fch));
      fch->tsn = htonl(gap_end);

      offset += sizeof(struct sctp_FORWARD_TSN);
    }

    size_t len = offset - (void *) resp_hdr;
    sctp_internal_send(sn, resp_hdr, len);
  }
*/
  return 0;
}

int sctp_received_HEARTBEAT(SN *sn, struct sctp_HEARTBEAT *ch) {
  char resp[sizeof(struct sctp_comm_hdr) + htons(ch->length)];
  struct sctp_comm_hdr *resp_hdr = (void *) resp;
  struct sctp_HEARTBEAT_ACK *rch = (void *) (resp + sizeof(*resp_hdr));

  resp_hdr->src_port = htons(5000);
  resp_hdr->dst_port = htons(5000);
  resp_hdr->verification = sn->ass->init_tag;

  memcpy(rch, ch, htons(ch->length));
  rch->type = 5;
  rch->flags = 0;
  
  return sctp_internal_send(sn, resp_hdr, sizeof(*resp_hdr) + htons(ch->length));
}

int sctp_received_COOKIE_ECHO(SN *sn, struct sctp_COOKIE_ECHO *ch) {
  char resp[sizeof(struct sctp_comm_hdr) + 4];
  struct sctp_comm_hdr *resp_hdr = (void *) resp;
  struct sctp_COOKIE_ACK *rch = (void *) (resp + sizeof(*resp_hdr));

  resp_hdr->src_port = htons(5000);
  resp_hdr->dst_port = htons(5000);
  resp_hdr->verification = sn->ass->init_tag;

  rch->type = 11;
  rch->flags = 0;
  rch->length = htons(4);
  
  return sctp_internal_send(sn, resp_hdr, sizeof(*resp_hdr) + 4);
}

int sctp_received_cb(SN *sn, char *buf, size_t len) {
  size_t off = 0;
  if (len < sizeof(struct sctp_comm_hdr))
    return -1;
  struct sctp_comm_hdr *hdr = (void *) buf;
  off += sizeof(struct sctp_comm_hdr);

  uint32_t realchks = hdr->checksum;
  hdr->checksum = 0;
  uint32_t checksum = crc32c(0, buf, len);
  if (checksum != realchks) {
    debug("Bad checksum %08x != %08x, len=%d\n", checksum, realchks, len);
    return -5;
  }
  hdr->checksum = realchks;


  while (off < len) {
    if (len - off < sizeof(struct sctp_chunk_hdr)) {
      debug("off=%d, len=%d\n", off, len);
      return -2;
    }

    struct sctp_chunk_hdr *ch = (void *) (buf + off);
    if (htons(ch->length) > len - off)
      return -3;

    switch (ch->type) {
      case 0:
        {
          debug("DATA\n");
          struct sctp_DATA *c = (void *) ch;
          int r = sctp_received_DATA(sn, c);
          if (r < 0) {
            fprintf(stderr, "DATA failed: %d\n", r);
            return -4;
          }
        } break;

      case 1:
        {
          debug("INIT\n");
          struct sctp_INIT *c = (void *) ch;
          int r = sctp_received_INIT(sn, c);
          if (r < 0) {
            fprintf(stderr, "INIT failed: %d\n", r);
            return -4;
          }
        } break;

      case 3:
        {
          debug("SACK\n");
          struct sctp_SACK *c = (void *) ch;
          int r = sctp_received_SACK(sn, c);
          if (r < 0) {
            fprintf(stderr, "SACK failed: %d\n", r);
            return -4;
          }
        } break;

      case 4:
        {
          debug("HEARTBEAT\n");
          struct sctp_HEARTBEAT *c = (void *) ch;
          int r = sctp_received_HEARTBEAT(sn, c);
          if (r < 0) {
            fprintf(stderr, "HEARTBEAT failed: %d\n", r);
            return -4;
          }
        } break;

      case 10:
        {
          debug("COOKIE ECHO\n");
          struct sctp_COOKIE_ECHO *c = (void *) ch;
          int r = sctp_received_COOKIE_ECHO(sn, c);
          if (r < 0) {
            fprintf(stderr, "COOKIE ECHO failed: %d\n", r);
            return -4;
          }
        } break;

      default:
        {
          debug("Unsupported chunk type %d\n", ch->type);
        }
    }

    // pad
    off += htons(ch->length);
    while (off % 4 != 0) off++;
  }

  return 0;
}

int sctp_send(SN *sn, char *data, size_t data_len) {
  if (sn->ass == NULL) {
    fprintf(stderr, "No association\n");
    return -1;
  }
  debug("Routing SCTP packet from %08x to SSL\n", htonl(sn->tun_addr.s_addr));
  char buf[2000];
  void *off = buf;

  struct sctp_comm_hdr *hdr = off;
  hdr->src_port = htons(5000);
  hdr->dst_port = htons(5000);
  hdr->verification = sn->ass->init_tag;
  off += sizeof(*hdr);

  struct sctp_FORWARD_TSN *fch = off;
  fch->type = 192;
  fch->flags = 0;
  fch->length = htons(sizeof(*fch));
  fch->tsn = htonl(sn->ass->snd_tsn - 1);
  off += sizeof(*fch);

  if (sn->ass->ack_required) {
    sn->ass->ack_required = 0;

    struct sctp_SACK *ach = off;
    ach->length = htons(sizeof(*ach));
    ach->type = 3;
    ach->flags = 0;
    ach->tsn = htonl(sn->ass->rcv_tsn);
    ach->a_rwnd = htonl(0x20000);
    ach->nogb = 0;
    ach->nodt = 0;
    off += sizeof(*ach);
  }

  struct sctp_DATA *dch = off;
  dch->length = htons(sizeof(*dch) + data_len);
  dch->type = 0;
  dch->flags = 7;
  dch->tsn = htonl(sn->ass->snd_tsn);
  dch->sid = 0;
  dch->ssn = 0;
  dch->ppid = htonl(51);
  off += sizeof(*dch);

  memcpy(off, data, data_len);
  off += data_len;

  while ((off - (void *) buf) % 4 != 0)
    off++;

  size_t total_len = off - (void *) buf;
  debug("Routing %dB SCTP packet from %08x to SSL\n", total_len, htonl(sn->tun_addr.s_addr));

  int r = sctp_internal_send(sn, hdr, total_len);

  /*
  struct sctp_FORWARD_TSN *fch = (void *) buf + sizeof(*hdr);
  fch->type = 192;
  fch->flags = 0;
  fch->length = htons(sizeof(*fch));
  fch->tsn = htonl(sn->ass->snd_tsn);
  total_len = sizeof(*hdr) + sizeof(*fch);
  sctp_internal_send(sn, hdr, total_len);
  */

  if (r >= 0) {
    sn->ass->snd_tsn++;
  }
  return r;
}


