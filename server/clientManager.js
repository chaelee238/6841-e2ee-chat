const {
  saveUser,
  getUser,
  storeMessage,
  bindSocketToUser,
  getSocket,
  unbindSocket,
} = require('./storage');

const { hashPassword, verifyPassword, isValidPassword } = require('./auth');

function handleConnection(socket) {
  let clientId = null;
  let buffer = '';

  socket.on('data', (data) => {
    buffer += data.toString();

    let boundary;
    while ((boundary = buffer.indexOf('\n')) !== -1) {
      const jsonStr = buffer.slice(0, boundary);
      buffer = buffer.slice(boundary + 1);

      let msg;
      try {
        msg = JSON.parse(jsonStr);
      } catch (e) {
        console.error('Invalid JSON:', e.message);
        continue;
      }

      if (msg.type === 'register') {
        const { id, password, publicKey } = msg;

        if (!id || !password) {
          socket.write(JSON.stringify({ type: 'error', message: 'Username and password required' }) + '\n');
          continue;
        }

        if (!isValidPassword(password)) {
          socket.write(JSON.stringify({ type: 'error', message: 'Password must be at least 8 chars and include a number' }) + '\n');
          continue;
        }

        if (getUser(id)) {
          socket.write(JSON.stringify({ type: 'error', message: 'User already exists. Please login.' }) + '\n');
          continue;
        }

        const { salt, hashedPassword } = hashPassword(password);

        saveUser(id, publicKey, salt, hashedPassword);

        bindSocketToUser(id, socket);
        clientId = id;

        socket.write(JSON.stringify({ type: 'success', message: 'Registration successful' }) + '\n');
        console.log(`User registered: ${id}`);

      } else if (msg.type === 'login') {
        const { id, password, publicKey } = msg;

        if (!id || !password) {
          socket.write(JSON.stringify({ type: 'error', message: 'Username and password required' }) + '\n');
          continue;
        }

        const user = getUser(id);

        if (!user) {
          socket.write(JSON.stringify({ type: 'error', message: 'User not found. Please register.' }) + '\n');
          continue;
        }

        if (!verifyPassword(password, user.salt, user.hashedPassword)) {
          socket.write(JSON.stringify({ type: 'error', message: 'Invalid password' }) + '\n');
          continue;
        }

        if (user.publicKey !== publicKey) {
          saveUser(id, publicKey, user.salt, user.hashedPassword);
        }

        bindSocketToUser(id, socket);
        clientId = id;

        socket.write(JSON.stringify({ type: 'success', message: 'Login successful' }) + '\n');
        console.log(`User logged in: ${id}`);

      } else if (msg.type === 'publicKeyRequest') {
        const user = getUser(msg.to);
        if (user) {
          socket.write(JSON.stringify({
            type: 'publicKeyResponse',
            to: clientId,
            from: msg.to,
            publicKey: user.publicKey
          }) + '\n');
        }
      } else if (msg.type === 'forward') {
        const targetSocket = getSocket(msg.to);
        if (targetSocket) {
          targetSocket.write(JSON.stringify({
            from: clientId,
            payload: msg.payload
          }) + '\n');

          storeMessage(clientId, msg.to, msg.payload);
        }
      }
    }
  });

  socket.on('end', () => {
    if (clientId) {
      unbindSocket(socket);
      console.log(`Client disconnected: ${clientId}`);
    }
  });

  socket.on('error', (err) => {
    console.error(`Socket error: ${err.message}`);
  });
}

module.exports = { handleConnection };
