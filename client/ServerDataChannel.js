'use strict';

function setupServerDataChannel(serverIP, serverPort, ufrag, pwd) {
  var endl = "\r\n";
  var offerSdp = {
    type: "offer",
    sdp: "v=0" + endl +
    "o=- 0 0 IN IP4 0.0.0.0" + endl +
    "s=-" + endl +
    "t=0 0" + endl +
    "m=application 1 DTLS/SCTP 5000" + endl +
    "c=IN IP4 0.0.0.0" + endl +
    "a=candidate:0 1 UDP 2000000000 " + serverIP + " " + serverPort + " typ host" + endl +
    "a=ice-ufrag:" + ufrag + endl +
    "a=ice-pwd:" + pwd + endl +
    "a=fingerprint:sha-256 3F:D2:A2:A6:92:2D:1C:A8:AD:C6:F5:1F:C5:9E:CB:C6:7A:18:9E:2E:C2:59:C5:0A:63:7F:38:02:F0:3C:DC:63" + endl +
    ""
  };

  var options = {
    ordered: false,
    maxRetransmits: 0,
    //maxPacketLifeTime: 0,
    id: 0,
    negotiated: true
  };

  var w = window;
  var PeerConnection = w.RTCPeerConnection || w.mozRTCPeerConnection || w.webkitRTCPeerConnection;
  var SessionDescription = w.RTCSessionDescription || w.mozRTCSessionDescription || w.RTCSessionDescription;
  var IceCandidate = w.RTCIceCandidate || w.mozRTCIceCandidate || w.RTCIceCandidate;

  var iceServers = { iceServers: [ { urls: [ 'stun:stun.l.google.com:19302' ] } ] };

  if (!navigator.onLine) {
    iceServers = null;
    console.warn('No internet connection detected.');
  }

  var peerConnection = new PeerConnection(iceServers);
  var channel = peerConnection.createDataChannel('channel', options);
  
  peerConnection.onicecandidate = function(e) { console.log('onicecandidate(' + JSON.stringify(e) + ')'); };
  var onSdpError = function(e) { console.error('onSdpError(' + JSON.stringify(e) + ')'); };
  var onSdpSuccess = function() { console.debug('onSdpSuccess()'); };

  var offerSDP = new SessionDescription(offerSdp);
  var constraints = { mandatory: { OfferToReceiveAudio: false, OfferToReceiveVideo: false } };
  peerConnection.setRemoteDescription(offerSDP, onSdpSuccess, onSdpError);
  peerConnection.createAnswer(function(sessionDescription) {
    peerConnection.setLocalDescription(sessionDescription);
  }, onSdpError, constraints);

  return channel;
};
