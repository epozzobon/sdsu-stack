(function() {
  var host = window.location.href;
  var protocol = host.substr(0, host.indexOf('://'));
  protocol = protocol === 'http' ? 'ws' : protocol === 'https' ? 'wss' : '';
  host = host.substr(host.indexOf('//') + 2);
  host = host.substr(0, host.lastIndexOf('/'));
  channel = new WebSocket(protocol + '://' + host + "/ws/echo");


	var latencyElement = window.document.getElementById('latency');
	var latencyArray = [];
	function logLatency(diff) {
		console.log(diff);
		latencyArray.push(diff);
		if (latencyArray.length > 100) {
			latencyArray.unshift();
		}

		var sumFunc = function(a, b) { return a + b; };
		var mean = latencyArray.reduce(sumFunc, 0) / latencyArray.length;
		var sqDev = latencyArray.map(function(a) { var dev = a - mean; return dev * dev; });
		var variance = sqDev.reduce(sumFunc, 0) / latencyArray.length;
		latencyElement.innerHTML = "Latency is " + diff + ",<br>Mean is " + mean + ",<br>Variance is " + variance;
	};


  channel.onopen = function (event) {
    window.setInterval(function () {
      channel.send("Hello, " + Date.now());
    }, 10);
  };

  channel.onmessage = function(event) {
    var diff = Date.now() - parseInt(event.data.substr(7));
    logLatency(diff);
  }
})();
