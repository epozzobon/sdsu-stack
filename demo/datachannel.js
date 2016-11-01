const exec = require('child_process').execFile;
const Buffer = require('buffer').Buffer;
const EventEmitter = require('events');
const dgram = require('dgram');

const datachannel = new EventEmitter();
module.exports = datachannel;

const users = {};
const unconfirmedUsers = {};

const apiClient = dgram.createSocket('udp4');
apiClient.on('message', function(buf) {
  console.log("Message from API");
  var offset = 0;
  var messageType = buf.readUInt8(offset++);
  switch (messageType) {
    case 1:
      {
        var usernameLength = buf.readUInt32LE(offset); offset += 4;
        var usernameArray = Array(usernameLength);
        for (var i = 0; i < usernameLength; i++)
          usernameArray[i] = buf.readUInt8(offset++);
        username = (usernameArray.map(function(c) { return String.fromCharCode(c); })).join("");
        var ip = Array.apply(null, Array(4)).map(function() { return ''+buf.readUInt8(offset++); }).join('.');

        console.log("Player " + username + " is " + ip);

        var user = unconfirmedUsers[username];
        if (!user)
          throw "Unexpected user '" + username + "' connected";
        delete unconfirmedUsers[username];
        users[ip] = user;
        user.tunAddr = ip;
        console.log("Player " + username + " confirmed");

      } break;
    default:
      {
        console.log("Unrecognised API response " + messageType);
      }
  }
});

apiClient.bind({ port: 39573, address: '10.64.0.1', exclusive: false });

datachannel.acceptUser = function(username, password) {
  var user = new EventEmitter();
  user.iceUsername = username;
  user.icePassword = password;
  user.tunAddr = null;
  user.send = function(buf) {
    datachannel.send(user, buf);
  };

  var offset = 0;
  var buf = new Buffer(8 + 1 + username.length + password.length);
  buf.writeUInt8(1, offset++);

  buf.writeUInt32LE(username.length, offset); offset += 4;
  for (var i = 0; i < username.length; i++)
    buf.writeUInt8(username.charCodeAt(i), offset++);

  buf.writeUInt32LE(password.length, offset); offset += 4;
  for (var i = 0; i < password.length; i++)
    buf.writeUInt8(password.charCodeAt(i), offset++);

  apiClient.send(buf, 0, buf.length, 39573, '10.79.255.254', function() {});

  unconfirmedUsers[username] = user;

  return user;
};

const sctp = dgram.createSocket('udp4');
sctp.on('message', function(buf, info) {
  var ip = info.address;
  var user = users[ip];
  if (user) {
    user.emit('message', buf);
  }
});
sctp.bind({ port: 5000, address: '10.64.0.1', exclusive: false });

datachannel.send = function(user, buf) {
  sctp.send(buf, 0, buf.length, 5000, user.tunAddr);
};

