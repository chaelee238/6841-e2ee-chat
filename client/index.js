const net = require('net');
const crypto = require('crypto');
const { ask, rl } = require('./prompt');
const {
  generateKeys,
  encryptRSA,
  decryptRSA,
  encryptAES,
  decryptAES,
  signMessage,
  verifySignature
} = require('../crypto');

(async () => {
  console.log("Welcome to E2EE Chat App!");
  
  let action;
  while (true) {
    action = (await ask("Do you want to (r)egister or (l)ogin? ")).toLowerCase();
    if (action === 'r' || action === 'l') break;
    console.log("Please enter 'r' to register or 'l' to login.");
  }

  const username = await ask("Username: ");
  const password = await ask("Password: ");

  const clientId = username;
  const { publicKey, privateKey } = generateKeys();

  let aesKey = null;
  let peerPublicKey = null;

  const socket = net.connect(1337);
  let buffer = '';

  let peer = null;

  socket.on('connect', () => {
    if (action === 'r') {
      socket.write(JSON.stringify({
        type: 'register',
        id: clientId,
        password,
        publicKey: publicKey.export({ format: 'pem', type: 'pkcs1' })
      }) + '\n');
    } else {
      socket.write(JSON.stringify({
        type: 'login',
        id: clientId,
        password,
        publicKey: publicKey.export({ format: 'pem', type: 'pkcs1' })
      }) + '\n');
    }
  });

  socket.on('data', async (data) => {
    buffer += data.toString();

    let boundary;
    while ((boundary = buffer.indexOf('\n')) !== -1) {
      const jsonStr = buffer.slice(0, boundary);
      buffer = buffer.slice(boundary + 1);

      try {
        const msg = JSON.parse(jsonStr);

        if (msg.type === 'success') {
          console.log(msg.message);

          peer = await ask("Chat with user: ");

          socket.write(JSON.stringify({
            type: 'publicKeyRequest',
            to: peer
          }) + '\n');

          rl.setPrompt(`${clientId}> `);
          rl.prompt();

        } else if (msg.type === 'error') {
          console.log("Error:", msg.message);
          console.log("Exiting.");
          socket.end();
          process.exit(1);

        } else if (msg.type === 'publicKeyResponse' && msg.to === clientId) {
          peerPublicKey = msg.publicKey;

          aesKey = crypto.randomBytes(32);

          const encryptedAESKey = encryptRSA(peerPublicKey, aesKey);

          socket.write(JSON.stringify({
            type: 'forward',
            to: peer,
            payload: {
              type: 'aesKey',
              data: encryptedAESKey.toString('base64')
            }
          }) + '\n');

          rl.setPrompt(`${clientId}> `);
          rl.prompt();

        } else if (msg.payload) {
          const { from, payload } = msg;

          if (payload.type === 'aesKey') {
            try {
              const decrypted = crypto.privateDecrypt({
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
              }, Buffer.from(payload.data, 'base64'));

              aesKey = decrypted;
              rl.prompt();
            } catch {
            }
          } else if (payload.type === 'message') {
            if (!aesKey) return;
          
            try {
              const encryptedBuffer = Buffer.from(payload.data, 'base64');
              const decrypted = decryptAES(aesKey, encryptedBuffer);
              const signatureBuffer = Buffer.from(payload.signature, 'base64');
          
              if (verifySignature(peerPublicKey, decrypted, signatureBuffer)) {
                console.log(`\n${from}: ${decrypted.toString()}`);
              } else {
                console.log(`\n${from}: Received message with invalid signature!`);
              }
            } catch (err) {
              console.log('Failed to decrypt or verify message:', err.message);
            }
            rl.prompt();
          }
        }
      } catch {
      }
    }
  });

  rl.on('line', (line) => {
    if (!aesKey) {
      console.log('AES key not set yet. Please wait.');
      rl.prompt();
      return;
    }
  
    const messageBuffer = Buffer.from(line);
    const signature = signMessage(privateKey, messageBuffer);
  
    const encrypted = encryptAES(aesKey, messageBuffer);
  
    socket.write(JSON.stringify({
      type: 'forward',
      to: peer,
      payload: {
        type: 'message',
        data: encrypted.toString('base64'),
        signature: signature.toString('base64')  
      }
    }) + '\n');
  
    rl.prompt();
  });
  

  rl.on('close', () => {
    console.log("Chat ended.");
    socket.end();
    process.exit(0);
  });
})();