
'use strict';

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = Number(process.env.PORT) || 10000;
const HOST = '0.0.0.0';

const VERSION = '2.1.0';
const NETWORK = 'SLX-Testnet';

const TRANSFER_FEE = 0.1;
const FAUCET_AMOUNT = 10;
const FAUCET_COOLDOWN_MS = 24 * 60 * 60 * 1000;

const DEMO_START_USDT = 10000;
const DEMO_START_SLX = 1000;
const DEMO_BASE_PRICE = 0.125;
const MAX_TRADE_AMOUNT = 1000000;

const JWT_SECRET =
  process.env.JWT_SECRET || 'SLX_TESTNET_SECRET_CHANGE_ME_2026';

const DATA_DIR =
  process.env.SLX_DATA_DIR || path.join(__dirname, 'data');

const DATA_FILE = path.join(DATA_DIR, 'slx-data.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

app.disable('x-powered-by');

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(self)');
  next();
});

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

/* ================================ DATABASE ================================ */

function emptyDB() {
  return {
    users: [],
    wallets: [],
    transactions: [],
    blocks: [],
    faucetClaims: [],
    demoAccounts: [],
demoTrades: [],
demoOrders: [],
network: {
      version: VERSION,
      name: NETWORK,
      height: 0,
      totalSupply: 0,
      genesisTime: Date.now()
    }
  };
}

function ensureDataFile() {
  fs.mkdirSync(DATA_DIR, { recursive: true });

  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(
      DATA_FILE,
      JSON.stringify(emptyDB(), null, 2),
      'utf8'
    );
  }
}

function round(value) {
  const n = Number(value);

  return Number.isFinite(n)
    ? Math.round((n + Number.EPSILON) * 1e8) / 1e8
    : 0;
}

function number(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function loadDB() {
  ensureDataFile();

  const parsed = JSON.parse(
    fs.readFileSync(DATA_FILE, 'utf8')
  );

  const defaults = emptyDB();

  for (const key of [
  'users',
  'wallets',
  'transactions',
  'blocks',
  'faucetClaims',
  'demoAccounts',
  'demoTrades',
  'demoOrders'
]) {
    parsed[key] = Array.isArray(parsed[key])
      ? parsed[key]
      : [];
  }

  parsed.network = {
    ...defaults.network,
    ...(parsed.network && typeof parsed.network === 'object'
      ? parsed.network
      : {})
  };

  for (const user of parsed.users) {
    if (!Object.prototype.hasOwnProperty.call(user, 'activeWalletId')) {
      user.activeWalletId = null;
    }

    if (!Number.isInteger(user.tokenVersion)) {
      user.tokenVersion = 0;
    }
  }

  for (const wallet of parsed.wallets) {
    wallet.balance = round(wallet.balance);
  }

  return parsed;
}

let db = loadDB();

function saveDB() {
  fs.mkdirSync(DATA_DIR, { recursive: true });

  const tempFile = `${DATA_FILE}.${process.pid}.tmp`;

  fs.writeFileSync(
    tempFile,
    JSON.stringify(db, null, 2),
    'utf8'
  );

  fs.renameSync(tempFile, DATA_FILE);
}

/* ================================= HELPERS ================================ */

function id(prefix = '') {
  return prefix + crypto.randomBytes(12).toString('hex');
}

function now() {
  return new Date().toISOString();
}

function walletAddress() {
  return 'SLXC' +
    crypto.randomBytes(16).toString('hex').toUpperCase();
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    createdAt: user.createdAt
  };
}

function publicWallet(wallet) {
  return {
    id: wallet.id,
    address: wallet.address,
    balance: round(wallet.balance),
    amount: round(wallet.balance),
    createdAt: wallet.createdAt
  };
}

function sendError(res, status, message) {
  return res.status(status).json({
    ok: false,
    error: message,
    message
  });
}

function getUserWallets(userId) {
  return db.wallets.filter(wallet => wallet.userId === userId);
}

function getWallet(userId, walletId) {
  return db.wallets.find(wallet =>
    wallet.userId === userId &&
    String(wallet.id) === String(walletId)
  );
}

function getWalletByAddress(address) {
  const normalized = String(address || '').trim().toUpperCase();

  return db.wallets.find(wallet =>
    String(wallet.address).toUpperCase() === normalized
  );
}

function activeWalletFor(user) {
  return (
    getWallet(user.id, user.activeWalletId) ||
    getUserWallets(user.id)[0] ||
    null
  );
}

function publicDemoAccount(account) {
  return {
    usdt: round(account.usdt),
    slx: round(account.slx),
    avgEntryPrice: round(account.avgEntryPrice),
    realizedPnl: round(account.realizedPnl),
    startingEquity: round(account.startingEquity),
    createdAt: account.createdAt
  };
}

function createDemoAccount(userId) {
  return {
    userId,
    usdt: DEMO_START_USDT,
    slx: DEMO_START_SLX,
    avgEntryPrice: DEMO_BASE_PRICE,
    realizedPnl: 0,
    startingEquity: round(
      DEMO_START_USDT + DEMO_START_SLX * DEMO_BASE_PRICE
    ),
    createdAt: now()
  };
}

function demoAccountFor(userId) {
  let account = db.demoAccounts.find(
    item => item.userId === userId
  );

  if (!account) {
    account = createDemoAccount(userId);
    db.demoAccounts.push(account);
  }

  return account;
}

/* Create demo portfolios for existing v2.0 users that do not have one. */
let migratedDemoAccounts = false;

for (const user of db.users) {
  if (!db.demoAccounts.some(item => item.userId === user.id)) {
    db.demoAccounts.push(createDemoAccount(user.id));
    migratedDemoAccounts = true;
  }
}

if (migratedDemoAccounts) {
  saveDB();
}

/* ================================= AUTH =================================== */

function hashRecoveryCode(code) {
  return crypto
    .createHash('sha256')
    .update(String(code || '').trim().toUpperCase())
    .digest('hex');
}

function recoveryCodeMatches(user, suppliedCode) {
  if (!user.recoveryCodeHash || !suppliedCode) {
    return false;
  }

  const a = Buffer.from(user.recoveryCodeHash, 'hex');
  const b = Buffer.from(hashRecoveryCode(suppliedCode), 'hex');

  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function createToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      username: user.username,
      ver: user.tokenVersion || 0
    },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || '';

  if (!header.startsWith('Bearer ')) {
    return sendError(res, 401, 'Требуется авторизация');
  }

  try {
    const decoded = jwt.verify(header.slice(7), JWT_SECRET);

    const user = db.users.find(
      item => item.id === decoded.userId
    );

    if (!user) {
      return sendError(res, 401, 'Пользователь не найден');
    }

    if (
      Number(decoded.ver || 0) !==
      Number(user.tokenVersion || 0)
    ) {
      return sendError(
        res,
        401,
        'Сессия завершена. Войди снова.'
      );
    }

    req.user = user;
    next();
  } catch (_error) {
    return sendError(res, 401, 'Недействительная сессия');
  }
}

/* ================================= HEALTH ================================= */

function healthPayload() {
  return {
    ok: true,
    name: 'SLX Network',
    version: VERSION,
    network: NETWORK,
    status: 'online',
    message: 'SLX Network server is running'
  };
}

app.get('/health', (_req, res) => {
  res.json(healthPayload());
});

app.get('/api/health', (_req, res) => {
  res.json(healthPayload());
});

app.get('/api/status', (_req, res) => {
  res.json({
    ...healthPayload(),
    networkVersion: VERSION,
    transferFee: TRANSFER_FEE,
    fee: TRANSFER_FEE,
    faucet: FAUCET_AMOUNT,
    height: db.blocks.length,
    blocks: db.blocks.length,
    users: db.users.length,
    wallets: db.wallets.length,
    totalSupply: round(db.network.totalSupply),
    uptime: process.uptime(),
    timestamp: now(),
    marketMode: 'SIMULATED_DEMO'
  });
});

/* ============================== TRANSACTIONS ============================== */

function addTransaction(data) {
  const transactionTime = now();

  const payload = {
    ...data,
    time: Date.now(),
    nonce: crypto.randomBytes(8).toString('hex')
  };

  const tx = {
    id: id('tx_'),
    hash: crypto
      .createHash('sha256')
      .update(JSON.stringify(payload))
      .digest('hex'),
    type: data.type || 'transfer',
    from: data.from || null,
    to: data.to || null,
    from_wallet: data.from || null,
    to_wallet: data.to || null,
    amount: round(data.amount || 0),
    fee: round(data.fee || 0),
    walletId: data.walletId || null,
    userId: data.userId || null,
    createdAt: transactionTime,
    created_at: transactionTime,
    timestamp: transactionTime,
    status: 'confirmed'
  };

  db.transactions.push(tx);
  return tx;
}

function transactionsForWallet(wallet) {
  const address = wallet.address.toUpperCase();

  return db.transactions.filter(tx =>
    String(tx.from || '').toUpperCase() === address ||
    String(tx.to || '').toUpperCase() === address ||
    String(tx.walletId || '') === String(wallet.id)
  ).slice().reverse();
}

function historyForUser(userId) {
  const addresses = new Set(
    getUserWallets(userId).map(wallet =>
      wallet.address.toUpperCase()
    )
  );

  return db.transactions.filter(tx =>
    addresses.has(String(tx.from || '').toUpperCase()) ||
    addresses.has(String(tx.to || '').toUpperCase())
  ).slice().reverse();
}

/* ================================ BLOCKCHAIN ============================== */

function calculateBlockHash(block) {
  return crypto
    .createHash('sha256')
    .update(JSON.stringify({
      index: block.index,
      previousHash: block.previousHash,
      transactions: block.transactions,
      timestamp: block.timestamp
    }))
    .digest('hex');
}

function createBlock(transaction) {
  const previous = db.blocks[db.blocks.length - 1];
  const index = db.blocks.length;

  const block = {
    index,
    height: index + 1,
    block_index: index,
    previousHash: previous ? previous.hash : '0'.repeat(64),
    transactions: [transaction],
    transaction_count: 1,
    timestamp: Date.now(),
    hash: ''
  };

  block.hash = calculateBlockHash(block);

  db.blocks.push(block);
  db.network.height = db.blocks.length;

  return block;
}

function verifyChain() {
  for (let i = 0; i < db.blocks.length; i++) {
    const block = db.blocks[i];

    const expectedPrevious = i === 0
      ? '0'.repeat(64)
      : db.blocks[i - 1].hash;

    if (block.previousHash !== expectedPrevious) {
      return {
        valid: false,
        error: `Ошибка previousHash в блоке ${i}`
      };
    }

    if (block.hash !== calculateBlockHash(block)) {
      return {
        valid: false,
        error: `Ошибка hash в блоке ${i}`
      };
    }
  }

  return { valid: true, error: null };
}

function createWalletForUser(userId, initial = false) {
  let address;

  do {
    address = walletAddress();
  } while (getWalletByAddress(address));

  const wallet = {
    id: id('WLT_').toUpperCase(),
    userId,
    address,
    balance: initial ? 100 : 0,
    createdAt: now()
  };

  db.wallets.push(wallet);

  if (initial) {
    db.network.totalSupply = round(
      db.network.totalSupply + wallet.balance
    );

    addTransaction({
      type: 'genesis',
      from: 'SLX_GENESIS',
      to: wallet.address,
      amount: wallet.balance,
      fee: 0,
      walletId: wallet.id,
      userId
    });
  }

  return wallet;
}

/* ================================= REGISTER =============================== */

app.post('/api/auth/register', async (req, res, next) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');

    if (username.length < 3 || username.length > 32) {
      return sendError(
        res,
        400,
        'Логин должен содержать от 3 до 32 символов'
      );
    }

    if (/[\u0000-\u001F\u007F]/.test(username)) {
      return sendError(res, 400, 'Недопустимые символы в логине');
    }

    if (password.length < 8 || password.length > 128) {
      return sendError(
        res,
        400,
        'Пароль должен содержать от 8 до 128 символов'
      );
    }

    if (db.users.some(
      user => user.username.toLowerCase() === username.toLowerCase()
    )) {
      return sendError(res, 409, 'Такой пользователь уже существует');
    }

    const recoveryCode =
      'SLX-' + crypto.randomBytes(4).toString('hex').toUpperCase();

    const user = {
      id: id('usr_'),
      username,
      passwordHash: await bcrypt.hash(password, 12),
      recoveryCodeHash: hashRecoveryCode(recoveryCode),
      createdAt: now(),
      activeWalletId: null,
      tokenVersion: 0
    };

    db.users.push(user);

    const wallet = createWalletForUser(user.id, true);
    user.activeWalletId = wallet.id;

    const demoAccount = createDemoAccount(user.id);
    db.demoAccounts.push(demoAccount);

    saveDB();

    const token = createToken(user);

    return res.status(201).json({
      ok: true,
      token,
      accessToken: token,
      recoveryCode,
      recovery_code: recoveryCode,
      user: publicUser(user),
      wallet: publicWallet(wallet),
      demoPortfolio: publicDemoAccount(demoAccount)
    });
  } catch (error) {
    next(error);
  }
});

/* ================================= LOGIN ================================== */

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');

    const user = db.users.find(
      item => item.username.toLowerCase() === username.toLowerCase()
    );

    if (
      !user ||
      !user.passwordHash ||
      !(await bcrypt.compare(password, user.passwordHash))
    ) {
      return sendError(res, 401, 'Неверный логин или пароль');
    }

    const token = createToken(user);

    res.json({
      ok: true,
      token,
      accessToken: token,
      user: publicUser(user)
    });
  } catch (error) {
    next(error);
  }
});

app.get('/api/auth/me', auth, (req, res) => {
  res.json({ ok: true, user: publicUser(req.user) });
});

app.post('/api/auth/logout', auth, (req, res) => {
  req.user.tokenVersion =
    Number(req.user.tokenVersion || 0) + 1;

  saveDB();

  res.json({ ok: true, message: 'Выход выполнен' });
});

/* ============================ PASSWORD CHANGE ============================= */

app.post('/api/auth/password/change', auth, async (req, res, next) => {
  try {
    const currentPassword = String(
      req.body?.currentPassword ||
      req.body?.oldPassword ||
      ''
    );

    const newPassword = String(req.body?.newPassword || '');

    if (newPassword.length < 8 || newPassword.length > 128) {
      return sendError(
        res,
        400,
        'Новый пароль должен содержать от 8 до 128 символов'
      );
    }

    if (!(await bcrypt.compare(currentPassword, req.user.passwordHash))) {
      return sendError(res, 400, 'Старый пароль указан неверно');
    }

    req.user.passwordHash = await bcrypt.hash(newPassword, 12);
    req.user.tokenVersion =
      Number(req.user.tokenVersion || 0) + 1;

    saveDB();

    const token = createToken(req.user);

    res.json({
      ok: true,
      token,
      accessToken: token,
      message: 'Пароль успешно изменён'
    });
  } catch (error) {
    next(error);
  }
});

/* ============================ PASSWORD RECOVERY =========================== */

app.post('/api/auth/recovery/reset', async (req, res, next) => {
  try {
    const username = String(req.body?.username || '').trim();

    const recoveryCode = String(
      req.body?.recoveryCode ||
      req.body?.recovery_code ||
      ''
    ).trim();

    const newPassword = String(
      req.body?.newPassword ||
      req.body?.password ||
      ''
    );

    if (!username || !recoveryCode || !newPassword) {
      return sendError(
        res,
        400,
        'Укажи логин, код восстановления и новый пароль'
      );
    }

    if (newPassword.length < 8 || newPassword.length > 128) {
      return sendError(res, 400, 'Пароль должен содержать от 8 до 128 символов');
    }

    const user = db.users.find(
      item => item.username.toLowerCase() === username.toLowerCase()
    );

    if (!user) {
      return sendError(res, 404, 'Пользователь не найден');
    }

    if (!recoveryCodeMatches(user, recoveryCode)) {
      return sendError(res, 403, 'Неверный код восстановления');
    }

    user.passwordHash = await bcrypt.hash(newPassword, 12);
    user.tokenVersion = Number(user.tokenVersion || 0) + 1;

    saveDB();

    const token = createToken(user);

    res.json({
      ok: true,
      token,
      accessToken: token,
      message: 'Пароль сброшен'
    });
  } catch (error) {
    next(error);
  }
});

/* ================================= WALLETS ================================ */

app.get('/api/wallets', auth, (req, res) => {
  const list = getUserWallets(req.user.id).map(publicWallet);

  res.json({ ok: true, wallets: list, data: list });
});

app.post('/api/wallet/create', auth, (req, res, next) => {
  try {
    const wallet = createWalletForUser(req.user.id, false);

    if (!req.user.activeWalletId) {
      req.user.activeWalletId = wallet.id;
    }

    saveDB();

    res.json({ ok: true, wallet: publicWallet(wallet) });
  } catch (error) {
    next(error);
  }
});

app.post('/api/wallet/select', auth, (req, res) => {
  const walletId = req.body?.walletId || req.body?.id;
  const wallet = getWallet(req.user.id, walletId);

  if (!wallet) {
    return sendError(res, 404, 'Кошелёк не найден');
  }

  req.user.activeWalletId = wallet.id;
  saveDB();

  res.json({ ok: true, wallet: publicWallet(wallet) });
});

app.get('/api/wallet/:id', auth, (req, res) => {
  const wallet = getWallet(req.user.id, req.params.id);

  if (!wallet) {
    return sendError(res, 404, 'Кошелёк не найден');
  }

  const transactions = transactionsForWallet(wallet);

  res.json({
    ok: true,
    wallet: publicWallet(wallet),
    transactions,
    history: transactions,
    data: { wallet: publicWallet(wallet), transactions }
  });
});

/* ================================= SEND SLX =============================== */

app.post('/api/send', auth, (req, res, next) => {
  try {
    const to = String(
      req.body?.to ||
      req.body?.toAddress ||
      req.body?.address ||
      ''
    ).trim().toUpperCase();

    const rawAmount = Number(req.body?.amount);
    const amount = round(rawAmount);

    const fromWalletId =
      req.body?.fromWalletId ||
      req.user.activeWalletId;

    const wallet =
      getWallet(req.user.id, fromWalletId) ||
      activeWalletFor(req.user);

    if (!/^SLXC[A-F0-9]{32}$/.test(to)) {
      return sendError(res, 400, 'Неверный адрес SLX');
    }

    if (!Number.isFinite(rawAmount) || amount <= 0) {
      return sendError(res, 400, 'Сумма должна быть больше 0');
    }

    if (!wallet) {
      return sendError(res, 400, 'Активный кошелёк не найден');
    }

    const recipient = getWalletByAddress(to);

    if (!recipient) {
      return sendError(
        res,
        404,
        'Кошелёк получателя не найден в тестовой сети'
      );
    }

    if (
      recipient.id === wallet.id ||
      recipient.userId === wallet.userId
    ) {
      return sendError(
        res,
        400,
        'Для теста используй кошелёк другого пользователя'
      );
    }

    const fee = TRANSFER_FEE;
    const total = round(amount + fee);

    if (wallet.balance + 1e-8 < total) {
      return sendError(res, 400, `Недостаточно SLX. Нужно ${total} SLX`);
    }

    wallet.balance = round(wallet.balance - total);
    recipient.balance = round(recipient.balance + amount);

    const tx = addTransaction({
      type: 'transfer',
      from: wallet.address,
      to: recipient.address,
      amount,
      fee,
      walletId: wallet.id,
      userId: req.user.id
    });

    createBlock(tx);
    saveDB();

    res.json({
      ok: true,
      transaction: tx,
      tx,
      fee,
      balance: wallet.balance
    });
  } catch (error) {
    next(error);
  }
});

/* ================================= FAUCET ================================= */

app.post('/api/faucet', auth, (req, res, next) => {
  try {
    const walletId =
      req.body?.walletId ||
      req.body?.id ||
      req.user.activeWalletId;

    const wallet = getWallet(req.user.id, walletId);

    if (!wallet) {
      return sendError(res, 404, 'Кошелёк не найден');
    }

    const existing = db.faucetClaims.find(
      claim => String(claim.walletId) === String(wallet.id)
    );

    const lastAt = existing ? Date.parse(existing.claimedAt) : 0;

    const remaining =
      FAUCET_COOLDOWN_MS -
      (Date.now() - (Number.isFinite(lastAt) ? lastAt : 0));

    if (existing && remaining > 0) {
      const message =
        `Faucet снова будет доступен примерно через ` +
        `${Math.ceil(remaining / 60000)} мин.`;

      return res.status(429).json({
        ok: false,
        error: message,
        message,
        cooldown: remaining
      });
    }

    wallet.balance = round(wallet.balance + FAUCET_AMOUNT);

    db.network.totalSupply = round(
      db.network.totalSupply + FAUCET_AMOUNT
    );

    if (existing) {
      existing.claimedAt = now();
    } else {
      db.faucetClaims.push({
        walletId: wallet.id,
        userId: req.user.id,
        claimedAt: now()
      });
    }

    const tx = addTransaction({
      type: 'faucet',
      from: 'SLX_FAUCET',
      to: wallet.address,
      amount: FAUCET_AMOUNT,
      fee: 0,
      walletId: wallet.id,
      userId: req.user.id
    });

    createBlock(tx);
    saveDB();

    res.json({
      ok: true,
      amount: FAUCET_AMOUNT,
      wallet: publicWallet(wallet),
      transaction: tx,
      tx
    });
  } catch (error) {
    next(error);
  }
});

/* ================================= HISTORY ================================ */

app.get('/api/transactions', auth, (req, res) => {
  const list = historyForUser(req.user.id);

  res.json({ ok: true, transactions: list, data: list });
});

app.get('/api/history', auth, (req, res) => {
  const list = historyForUser(req.user.id);

  res.json({
    ok: true,
    history: list,
    transactions: list,
    data: list
  });
});

/* ================================= BLOCKS ================================= */

app.get('/api/blocks', (req, res) => {
  const rawLimit = Number.parseInt(String(req.query.limit || '20'), 10);
  const limit = Math.max(1, Math.min(rawLimit || 20, 100));
  const blocks = db.blocks.slice(-limit).reverse();

  res.json({
    ok: true,
    blocks,
    count: db.blocks.length,
    height: db.blocks.length,
    data: blocks
  });
});

app.get('/api/economy', (_req, res) => {
  const circulating = db.wallets.reduce(
    (sum, wallet) => sum + number(wallet.balance),
    0
  );

  res.json({
    ok: true,
    network: NETWORK,
    version: VERSION,
    totalSupply: round(db.network.totalSupply),
    circulatingSupply: round(circulating),
    maxSupply: null,
    users: db.users.length,
    wallets: db.wallets.length,
    transactions: db.transactions.length,
    blocks: db.blocks.length,
    transferFee: TRANSFER_FEE,
    faucetAmount: FAUCET_AMOUNT
  });
});

function sendChainVerification(_req, res) {
  const result = verifyChain();

  res.json({
    ok: result.valid,
    valid: result.valid,
    verified: result.valid,
    blocks: db.blocks.length,
    error: result.error
  });
}

app.get('/api/chain/verify', sendChainVerification);
app.post('/api/chain/verify', sendChainVerification);

app.get('/api/debug', auth, (req, res) => {
  res.json({
    version: VERSION,
    network: NETWORK,
    user: publicUser(req.user),
    wallets: getUserWallets(req.user.id).map(publicWallet),
    demoPortfolio: publicDemoAccount(demoAccountFor(req.user.id)),
    database: {
      users: db.users.length,
      wallets: db.wallets.length,
      transactions: db.transactions.length,
      blocks: db.blocks.length,
      faucetClaims: db.faucetClaims.length,
      demoAccounts: db.demoAccounts.length,
      demoTrades: db.demoTrades.length
    }
  });
});

/* ================================ DEMO MARKET ============================== */

const MARKET = Object.freeze({
  pair: 'SLX/USDT',
  baseAsset: 'SLX',
  quoteAsset: 'USDT',
  basePrice: DEMO_BASE_PRICE,
  source: 'SIMULATED_TEST_DATA'
});

const intervalMap = Object.freeze({
  '15m': 15 * 60 * 1000,
  '1h': 60 * 60 * 1000,
  '4h': 4 * 60 * 60 * 1000,
  '1d': 24 * 60 * 60 * 1000
});

function wave(seed) {
  const x = Math.sin(seed * 12.9898 + 78.233) * 43758.5453;
  return (x - Math.floor(x)) * 2 - 1;
}

function simulatedPriceAt(timestamp) {
  const t = Number(timestamp);

  const trend = Math.sin(t / (1000 * 60 * 60 * 7.3)) * 0.045;
  const mid = Math.sin(t / (1000 * 60 * 83)) * 0.023;
  const short = Math.sin(t / (1000 * 60 * 17)) * 0.009;
  const noise = wave(Math.floor(t / (1000 * 60 * 5))) * 0.004;

  return Math.max(
    0.001,
    round(MARKET.basePrice * (1 + trend + mid + short + noise))
  );
}

function makeCandles(interval, requestedLimit) {
  const step = intervalMap[interval] || intervalMap['1h'];

  const limit = Math.max(
    10,
    Math.min(100, Number(requestedLimit) || 60)
  );

  const end = Math.floor(Date.now() / step) * step;
  const candles = [];

  for (let i = limit - 1; i >= 0; i--) {
    const time = end - i * step;

    const open = simulatedPriceAt(time);
    const close = simulatedPriceAt(time + step - 1);

    const spreadHigh = 0.001 + Math.abs(wave(time / step + 11)) * 0.009;
    const spreadLow = 0.001 + Math.abs(wave(time / step + 29)) * 0.009;

    const high = round(Math.max(open, close) * (1 + spreadHigh));
    const low = round(
      Math.max(0.001, Math.min(open, close) * (1 - spreadLow))
    );

    const volume = round(
      500 + Math.abs(wave(time / step + 91)) * 14500
    );

    candles.push({ time, open, high, low, close, volume });
  }

  return candles;
}

function marketTicker() {
  const currentTime = Date.now();
  const price = simulatedPriceAt(currentTime);

  const previous = simulatedPriceAt(
    currentTime - 24 * 60 * 60 * 1000
  );

  const change = round(price - previous);
  const changePercent = previous
    ? round((change / previous) * 100)
    : 0;

  const dayCandles = makeCandles('1h', 24);

  return {
    ok: true,
    demo: true,
    simulated: true,
    mode: 'DEMO / TESTNET',
    source: MARKET.source,
    pair: MARKET.pair,
    baseAsset: MARKET.baseAsset,
    quoteAsset: MARKET.quoteAsset,
    price,
    lastPrice: price,
    change24h: change,
    changePercent24h: changePercent,
    priceChangePercent: changePercent,
    volume24h: round(
      dayCandles.reduce((sum, candle) => sum + candle.volume, 0)
    ),
    high24h: round(Math.max(...dayCandles.map(candle => candle.high))),
    low24h: round(Math.min(...dayCandles.map(candle => candle.low))),
    timestamp: currentTime
  };
}

function marketDepth() {
  const price = simulatedPriceAt(Date.now());
  const bids = [];
  const asks = [];

  for (let i = 1; i <= 12; i++) {
    bids.push({
      price: round(price * (1 - i * 0.0012)),
      amount: round(40 + Math.abs(wave(i * 13 + 2)) * 900),
      total: 0
    });

    asks.push({
      price: round(price * (1 + i * 0.0012)),
      amount: round(40 + Math.abs(wave(i * 19 + 3)) * 900),
      total: 0
    });
  }

  for (const side of [bids, asks]) {
    let total = 0;

    for (const row of side) {
      total = round(total + row.amount);
      row.total = total;
    }
  }

  return {
    ok: true,
    demo: true,
    simulated: true,
    pair: MARKET.pair,
    bids,
    asks,
    spread: round(asks[0].price - bids[0].price),
    timestamp: Date.now()
  };
}

function marketTrades() {
  const currentTime = Date.now();
  const items = [];

  for (let i = 0; i < 24; i++) {
    const time =
      currentTime -
      i * (20000 + Math.floor(Math.abs(wave(i + 300)) * 45000));

    items.push({
      id: `demo-${Math.floor(time / 1000)}-${i}`,
      price: simulatedPriceAt(time),
      amount: round(0.5 + Math.abs(wave(i * 7 + 22)) * 200),
      side: wave(i * 5 + 9) > 0 ? 'buy' : 'sell',
      time
    });
  }

  return items;
}

function demoPortfolioPayload(account) {
  const price = marketTicker().price;
  const marketValue = round(account.slx * price);
  const equity = round(account.usdt + marketValue);

  const unrealizedPnl = round(
    (price - number(account.avgEntryPrice)) * account.slx
  );

  return {
    usdt: round(account.usdt),
    slx: round(account.slx),
    demoUSDT: round(account.usdt),
    demoSLX: round(account.slx),
    currentPrice: price,
    slxValue: marketValue,
    marketValue,
    totalEquity: equity,
    startingEquity: round(account.startingEquity),
    avgEntryPrice: round(account.avgEntryPrice),
    realizedPnl: round(account.realizedPnl),
    unrealizedPnl,
    totalPnl: round(account.realizedPnl + unrealizedPnl),
    pair: MARKET.pair,
    demo: true
  };
}

function executeDemoBuy(req, res) {
  const account = demoAccountFor(req.user.id);
  const quantity = round(number(req.body?.amount ?? req.body?.quantity));

  if (!Number.isFinite(Number(req.body?.amount ?? req.body?.quantity)) ||
      quantity <= 0 || quantity > MAX_TRADE_AMOUNT) {
    return sendError(res, 400, 'Укажи корректное количество SLX');
  }

  const price = marketTicker().price;
  const total = round(quantity * price);

  if (account.usdt + 1e-8 < total) {
    return sendError(
      res,
      400,
      `Недостаточно Demo USDT. Нужно ${total} USDT`
    );
  }

  const oldQuantity = account.slx;
  const newQuantity = round(oldQuantity + quantity);

  account.avgEntryPrice = newQuantity > 0
    ? round(
        (
          oldQuantity * number(account.avgEntryPrice) +
          quantity * price
        ) / newQuantity
      )
    : 0;

  account.usdt = round(account.usdt - total);
  account.slx = newQuantity;

  const trade = {
    id: id('demo_'),
    userId: req.user.id,
    side: 'buy',
    type: 'buy',
    pair: MARKET.pair,
    amount: quantity,
    quantity,
    price,
    total,
    quoteAsset: 'Demo USDT',
    status: 'simulated',
    demo: true,
    createdAt: now()
  };

  db.demoTrades.push(trade);
  saveDB();

  res.json({
    ok: true,
    message: 'Демо-покупка выполнена',
    trade,
    portfolio: demoPortfolioPayload(account)
  });
}

function executeDemoSell(req, res) {
  const account = demoAccountFor(req.user.id);
  const quantity = round(number(req.body?.amount ?? req.body?.quantity));

  if (!Number.isFinite(Number(req.body?.amount ?? req.body?.quantity)) ||
      quantity <= 0 || quantity > MAX_TRADE_AMOUNT) {
    return sendError(res, 400, 'Укажи корректное количество SLX');
  }

  if (quantity > account.slx + 1e-8) {
    return sendError(res, 400, 'Недостаточно Demo SLX');
  }

  const price = marketTicker().price;
  const total = round(quantity * price);

  account.slx = round(Math.max(0, account.slx - quantity));
  account.usdt = round(account.usdt + total);

  account.realizedPnl = round(
    account.realizedPnl +
    (price - number(account.avgEntryPrice)) * quantity
  );

  if (account.slx <= 1e-8) {
    account.slx = 0;
    account.avgEntryPrice = 0;
  }

  const trade = {
    id: id('demo_'),
    userId: req.user.id,
    side: 'sell',
    type: 'sell',
    pair: MARKET.pair,
    amount: quantity,
    quantity,
    price,
    total,
    quoteAsset: 'Demo USDT',
    status: 'simulated',
    demo: true,
    createdAt: now()
  };

  db.demoTrades.push(trade);
  saveDB();

  res.json({
    ok: true,
    message: 'Демо-продажа выполнена',
    trade,
    portfolio: demoPortfolioPayload(account)
  });
}

/* Demo portfolio and trading endpoints. */
app.get('/api/demo/portfolio', auth, (req, res) => {
  const account = demoAccountFor(req.user.id);

  res.json({
    ok: true,
    demo: true,
    portfolio: demoPortfolioPayload(account)
  });
});

app.get('/api/demo/trades', auth, (req, res) => {
  const rawLimit = Number.parseInt(String(req.query.limit || '50'), 10);
  const limit = Math.max(1, Math.min(rawLimit || 50, 200));

  const trades = db.demoTrades
    .filter(trade => trade.userId === req.user.id)
    .slice(-limit)
    .reverse();

  res.json({
    ok: true,
    demo: true,
    trades,
    data: trades
  });
});

app.get('/api/demo/history', auth, (req, res) => {
  const trades = db.demoTrades
    .filter(trade => trade.userId === req.user.id)
    .slice()
    .reverse();

  res.json({ ok: true, demo: true, trades, data: trades });
});

app.post('/api/demo/buy', auth, executeDemoBuy);
app.post('/api/demo/sell', auth, executeDemoSell);

/* Aliases for market pages that use /api/market/buy or /sell. */
app.post('/api/market/buy', auth, executeDemoBuy);
app.post('/api/market/sell', auth, executeDemoSell);

/* Read-only simulated market endpoints. No external exchange is connected. */
app.get('/api/market', (_req, res) => res.json(marketTicker()));
app.get('/api/market/ticker', (_req, res) => res.json(marketTicker()));
app.get('/api/market/summary', (_req, res) => res.json(marketTicker()));

app.get('/api/market/candles', (req, res) => {
  const interval = intervalMap[req.query.interval]
    ? req.query.interval
    : '1h';

  const candles = makeCandles(interval, req.query.limit);

  res.json({
    ok: true,
    demo: true,
    simulated: true,
    pair: MARKET.pair,
    interval,
    candles,
    data: candles,
    timestamp: Date.now()
  });
});

app.get('/api/market/depth', (_req, res) => res.json(marketDepth()));
app.get('/api/market/orderbook', (_req, res) => res.json(marketDepth()));

app.get('/api/market/trades', (_req, res) => {
  const trades = marketTrades();

  res.json({
    ok: true,
    demo: true,
    simulated: true,
    pair: MARKET.pair,
    trades,
    data: trades
  });
});

app.get('/api/market/history', (req, res) => {
  const interval = intervalMap[req.query.interval]
    ? req.query.interval
    : '1h';

  const candles = makeCandles(interval, req.query.limit || 60);

  res.json({
    ok: true,
    demo: true,
    simulated: true,
    pair: MARKET.pair,
    interval,
    history: candles,
    candles,
    data: candles
  });
});

/* ============================== FRONTEND STATIC =========================== */

function findIndexFile() {
  const candidates = [
    path.join(PUBLIC_DIR, 'index.html'),
    path.join(__dirname, 'index.html')
  ];

  return candidates.find(file => {
    try {
      return fs.statSync(file).isFile();
    } catch (_error) {
      return false;
    }
  }) || null;
}

if (fs.existsSync(PUBLIC_DIR)) {
  app.use(express.static(PUBLIC_DIR, {
    index: 'index.html',
    fallthrough: true
  }));
}

app.get('/', (_req, res) => {
  const indexFile = findIndexFile();

  if (indexFile) {
    return res.sendFile(indexFile);
  }

  return res.status(503).json({
    ok: false,
    status: 'frontend_missing',
    version: VERSION,
    message:
      'Сервер работает, но HTML интерфейса не найден. ' +
      'Добавь index.html в корень проекта или public/index.html.'
  });
});

app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({
      ok: false,
      error: 'API endpoint not found',
      message: 'API endpoint not found'
    });
  }

  if (req.method === 'GET') {
    const indexFile = findIndexFile();

    if (indexFile) {
      return res.sendFile(indexFile);
    }
  }

  next();
});

/* ============================== ERROR HANDLER ============================= */

app.use((err, _req, res, _next) => {
  console.error(
    '[SLX] SERVER ERROR:',
    err && (err.stack || err.message || err)
  );

  if (res.headersSent) return;

  res.status(500).json({
    ok: false,
    error: 'Внутренняя ошибка сервера',
    message: 'Внутренняя ошибка сервера'
  });
});

/* ================================= START ================================== */

app.listen(PORT, HOST, () => {
  console.log('====================================');
  console.log('        SLX NETWORK SERVER');
  console.log('====================================');
  console.log('Version:', VERSION);
  console.log('Network:', NETWORK);
  console.log('Port:', PORT);
  console.log('Data file:', DATA_FILE);
  console.log('Frontend:', findIndexFile() || 'NOT FOUND');
  console.log('Market:', `${MARKET.pair} (SIMULATED DEMO)`);
  console.log('Demo portfolios:', db.demoAccounts.length);
  console.log('Status: ONLINE');

  if (!process.env.JWT_SECRET) {
    console.warn(
      '[SLX] Set JWT_SECRET in Render Environment before deployment.'
    );
  }

  console.log('====================================');
});
