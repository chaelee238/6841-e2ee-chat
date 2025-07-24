const net = require('net');
const { handleConnection } = require('./clientManager');

const server = net.createServer(handleConnection);

server.listen(1337, () => console.log('Server running on port 1337'));
