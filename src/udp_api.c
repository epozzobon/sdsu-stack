#include "webrtc_server.h"

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

