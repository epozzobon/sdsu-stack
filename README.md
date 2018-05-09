# sdsu-stack
UDP communication between the browser and the server using WebRTC DataChannel.

This project is just a proof-of-concept. It contains insecure implementations of STUN, SCTP, UDP and even IP, so it should not be user anywhere. Ever.

Compile it:
```bash
gcc src/*.c -lssl -lcrypto -o webrtc_server
```

Run make_tun.sh in order to to setup the TUN virtual device, then run webrtc_server:
```bash
sudo ./make_tun.sh
./webrtc_server
```

After enstablishing the DTLS and SCTP sessions, the payload of SCTP packets from the browser will be mapped onto UDP packets on the TUN device.

The demo directory contains a nodejs application to compare websockets latency with webrtc datachannels. To run it, set the server IP address in demo/routes/index.js, then run the demo:
```bash
cd demo
$EDITOR routes/index.js
# Change the serverIP field
npm install
bin/www
```

Point your browser to http://localhost:4000 to see the demo.

Currently tested on Chromium 66.0.3359.117 (Official Build) Arch Linux (64-bit).
