var express = require('express');
var router = express.Router();

router.ws('/echo', function(ws, req) {
  console.log('connect');
  ws.pleaseWait = true;

  ws.on('message', function(msg) {
    ws.send(msg);
  });
});

module.exports = router;
