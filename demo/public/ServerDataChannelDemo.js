var serverIP = window.document.getElementById('server-ip').value;
var serverPort = window.document.getElementById('server-port').value;
var iceUsername = window.document.getElementById('ice-username').value;
var icePassword = window.document.getElementById('ice-password').value;

var channel = setupServerDataChannel(serverIP, serverPort, iceUsername, icePassword);

channel.onopen = function (event) {
  window.setInterval(function () {
    channel.send("Hello, " + Date.now());
  }, 10);
};

channel.onmessage = function (event) {
  var diff = Date.now() - parseInt(event.data.substr(7));
  console.log(diff);
};
