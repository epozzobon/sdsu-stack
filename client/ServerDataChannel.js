'use strict';

function setupServerDataChannel(serverIP, serverPort, fingerprint, ufrag, pwd) {
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
    "a=fingerprint:" + fingerprint + endl +
    ""
  };

	console.log("offerSdp.sdp='" + offerSdp.sdp + "'");

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
