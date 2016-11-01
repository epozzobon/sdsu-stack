(function() {
  var host = window.location.href;
  var protocol = host.substr(0, host.indexOf('://'));
  protocol = protocol === 'http' ? 'ws' : protocol === 'https' ? 'wss' : '';
  host = host.substr(host.indexOf('//') + 2);
  host = host.substr(0, host.lastIndexOf('/'));
  channel = new WebSocket(protocol + '://' + host + "/ws/echo");

  channel.onopen = function (event) {
    window.setInterval(function () {
      channel.send("Hello, " + Date.now());
    }, 10);
  };

  channel.onmessage = function(event) {
    var diff = Date.now() - parseInt(event.data.substr(7));
    console.log(diff);
  }
})();
