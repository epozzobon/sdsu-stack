#include "webrtc_server.h"

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

