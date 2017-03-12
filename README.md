# sdsu-stack
UDP communication between the browser and the server using WebRTC DataChannel

This project is just a proof-of-concept. It contains insecure implementations of STUN, SCTP, UDP and even IP, so it should not be user anywhere. Ever.

Compile it:
```bash
gcc src/*.c -lssl -lcrypto -o webrtc_server
```

Run make_tun.sh in order to to setup the TUN virtual device, then run webrtc_server:
```bash
make_tun.sh
webrtc_server
```

After enstablishing the DTLS and SCTP sessions, the payload of SCTP packets from the browser will be mapped onto UDP packets on the TUN device.

The demo directory contains a nodejs application to compare websockets latency with webrtc datachannels. To run it, set the server IP address in demo/routes/index.js, then run the demo:
```bash
cd demo
bin/www
```

Point your browser to port 4000 to see the demo.

Currently this only works with chromium and google chrome, or maybe not even that.
