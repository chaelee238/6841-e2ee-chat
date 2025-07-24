const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = path.join(__dirname, '..', 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR);
}

let users = {};
if (fs.existsSync(USERS_FILE)) {
  try {
    users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch (err) {
    console.error('Failed to parse users.json:', err);
  }
}

let messages = [];
if (fs.existsSync(MESSAGES_FILE)) {
  try {
    messages = JSON.parse(fs.readFileSync(MESSAGES_FILE, 'utf8'));
  } catch (err) {
    console.error('Failed to parse messages.json:', err);
  }
}

const sockets = {};

function hashPassword(password, salt = null) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hashedPassword = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hashedPassword };
}

function verifyPassword(password, salt, hashedPassword) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return hash === hashedPassword;
}

function saveUser(id, publicKey, salt, hashedPassword) {
  users[id] = { id, salt, hashedPassword, publicKey };
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  console.log(`Saved user "${id}" to ${USERS_FILE}`);
}

function getUser(id) {
  return users[id];
}

function storeMessage(from, to, payload) {
  messages.push({ from, to, payload });
  fs.writeFileSync(MESSAGES_FILE, JSON.stringify(messages, null, 2));
}

function bindSocketToUser(id, socket) {
  sockets[id] = socket;
}

function getSocket(id) {
  return sockets[id];
}

function unbindSocket(socket) {
  for (const [id, s] of Object.entries(sockets)) {
    if (s === socket) {
      delete sockets[id];
      break;
    }
  }
}

module.exports = {
  saveUser,
  getUser,
  verifyPassword,
  storeMessage,
  bindSocketToUser,
  getSocket,
  unbindSocket,
  sockets
};
