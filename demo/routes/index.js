var express = require('express');
var datachannel = require('../datachannel');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Index' });
});

router.get('/ws-demo', function(req, res, next) {
  res.render('ws-demo', { title: 'WebSocket Demo' });
});

router.get('/dc-demo', function(req, res, next) {
  var iceUsername = Math.random().toString(36).substr(2);
  var icePassword = 'gBNbKCaDDslY8Gf8BNZ8kfGr';
	var fingerprint = 'sha-256 56:44:51:8E:14:56:BD:5A:BC:9C:2E:5F:AE:22:C8:5A:8F:EF:5C:E0:DD:70:1D:08:54:06:86:78:97:43:7D:F8';
  var user = datachannel.acceptUser(iceUsername, icePassword);

  user.on('message', function(buf) {
    user.send(buf);
  });

  res.render('dc-demo', {
    title: 'Server WebRTC DataChannel Demo',
    iceUsername: user.iceUsername,
    icePassword: user.icePassword,
    fingerprint: fingerprint,
    serverIP: '192.168.2.114',
    serverPort: '10000'
  });

});

module.exports = router;
