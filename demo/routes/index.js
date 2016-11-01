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
  var user = datachannel.acceptUser(iceUsername, icePassword);

  user.on('message', function(buf) {
    user.send(buf);
  });

  res.render('dc-demo', {
    title: 'Server WebRTC DataChannel Demo',
    iceUsername: user.iceUsername,
    icePassword: user.icePassword,
    serverIP: '192.168.1.1',
    serverPort: '10000'
  });

});

module.exports = router;
