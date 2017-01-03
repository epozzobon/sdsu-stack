# sdsu-stack
UDP communication between the browser and the server using WebRTC DataChannel

This project is just a proof-of-concept. It contains insecure implementations of STUN, SCTP, UDP and even IP, so it should not be user anywhere. Ever.

Compile it:
```bash
cd build
cmake ..
make
```

Run make_tun.sh in order to to setup the TUN virtual device, then run webrtc_server.
The demo directory contains a nodejs application to compare websockets latency with webrtc.

Currently this only works with chromium, or maybe not even that.
