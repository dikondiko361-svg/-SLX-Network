const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 10000;
const JWT_SECRET =
  process.env.JWT_SECRET ||
  "SLX_NETWORK_V1_9_CHANGE_THIS_SECRET";

const DATA_FILE = path.join(__dirname, "slx-data.json");

app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

/* ============================================================
   DATABASE
============================================================ */

function emptyDatabase() {
  return {
    version: "1.9.0",

    users: [],

    wallets: [],

    transactions: [],

    blocks: [
      {
        index: 0,
        timestamp: Date.now(),
        transactions: [],
        previousHash: "0",
        hash: "GENESIS"
      }
    ],

    network: {
      name: "SLX Testnet",
      networkId: "SLX-TESTNET-1"
    }
  };
}

function loadDatabase() {
  try {
    if (!fs.existsSync(DATA_FILE)) {
      const db = emptyDatabase();
      saveDatabase(db);
      return db;
    }

    const raw = fs.readFileSync(DATA_FILE, "utf8");
    const db = JSON.parse(raw);

    if (!db.users) db.users = [];
    if (!db.wallets) db.wallets = [];
    if (!db.transactions) db.transactions = [];
    if (!db.blocks || !Array.isArray(db.blocks)) {
      db.blocks = emptyDatabase().blocks;
    }

    if (!db.network) {
      db.network = {
        name: "SLX Testnet",
        networkId: "SLX-TESTNET-1"
      };
    }

    return db;

  } catch (err) {
    console.error("DATABASE LOAD ERROR:", err);

    const db = emptyDatabase();
    saveDatabase(db);

    return db;
  }
}

let db = loadDatabase();

function saveDatabase(database = db) {
  const tempFile = DATA_FILE + ".tmp";

  fs.writeFileSync(
    tempFile,
    JSON.stringify(database, null, 2),
    "utf8"
  );

  fs.renameSync(tempFile, DATA_FILE);
}

/* ============================================================
   HELPERS
============================================================ */

function makeId() {
  return crypto.randomUUID();
}

function makeAddress() {
  return (
    "SLXC" +
    crypto.randomBytes(16).toString("hex").toUpperCase()
  );
}

function makeRecoveryCode() {
  return (
    "SLX-" +
    crypto.randomBytes(4).toString("hex").toUpperCase() +
    "-" +
    crypto.randomBytes(4).toString("hex").toUpperCase()
  );
}

function makeHash(data) {
  return crypto
    .createHash("sha256")
    .update(data)
    .digest("hex");
}

function now() {
  return Date.now();
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
    userId: wallet.userId,
    address: wallet.address,
    balance: Number(wallet.balance || 0),
    createdAt: wallet.createdAt
  };
}

function roundSLX(value) {
  return Math.round(Number(value) * 100000000) / 100000000;
}

/* ============================================================
   JWT
============================================================ */

function createToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      username: user.username
    },
    JWT_SECRET,
    {
      expiresIn: "30d"
    }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      ok: false,
      message: "Требуется авторизация."
    });
  }

  const token = header.substring(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const user = db.users.find(
      u => u.id === decoded.userId
    );

    if (!user) {
      return res.status(401).json({
        ok: false,
        message: "Пользователь не найден."
      });
    }

    req.user = user;

    next();

  } catch {
    return res.status(401).json({
      ok: false,
      message: "Сессия недействительна или истекла."
    });
  }
}

/* ============================================================
   BLOCKCHAIN
============================================================ */

function calculateBlockHash(block) {
  return makeHash(
    JSON.stringify({
      index: block.index,
      timestamp: block.timestamp,
      transactions: block.transactions,
      previousHash: block.previousHash
    })
  );
}

function createBlock(transactionIds = []) {
  const previous =
    db.blocks[db.blocks.length - 1];

  const block = {
    index: db.blocks.length,
    timestamp: now(),
    transactions: transactionIds,
    previousHash: previous
      ? previous.hash
      : "0",
    hash: ""
  };

  block.hash = calculateBlockHash(block);

  db.blocks.push(block);

  saveDatabase();

  return block;
}

/* ============================================================
   HEALTH
============================================================ */

app.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "index.html")
  );
});

app.get("/api/status", (req, res) => {
  res.json({
    ok: true,
    version: "1.9.0",
    networkVersion: "1.9.0",
    networkId: "SLX-TESTNET-1",
    status: "online",
    blockHeight:
      Math.max(db.blocks.length - 1, 0),
    blocks: db.blocks.length,
    wallets: db.wallets.length
  });
});

/* ============================================================
   ECONOMY
============================================================ */

app.get("/api/economy", (req, res) => {

  const circulatingSupply =
    db.wallets.reduce(
      (sum, wallet) =>
        sum + Number(wallet.balance || 0),
      0
    );

  res.json({
    ok: true,

    maxSupply: 21000000,

    circulatingSupply:
      roundSLX(circulatingSupply)
  });
});

/* ============================================================
   REGISTER
============================================================ */

app.post("/api/auth/register", async (req, res) => {

  try {

    const username =
      String(req.body.username || "").trim();

    const password =
      String(req.body.password || "");

    if (
      !/^[a-zA-Z0-9_]{3,32}$/.test(username)
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Имя: 3–32 символа, только буквы, цифры и _."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        ok: false,
        message:
          "Пароль должен содержать минимум 6 символов."
      });
    }

    const exists =
      db.users.some(
        u =>
          u.username.toLowerCase() ===
          username.toLowerCase()
      );

    if (exists) {
      return res.status(409).json({
        ok: false,
        message:
          "Такое имя пользователя уже существует."
      });
    }

    const userId = makeId();

    const passwordHash =
      await bcrypt.hash(password, 12);

    const recoveryCode =
      makeRecoveryCode();

    const recoveryHash =
      await bcrypt.hash(recoveryCode, 12);

    const user = {
      id: userId,
      username,
      passwordHash,
      recoveryHash,
      createdAt: new Date().toISOString()
    };

    db.users.push(user);

    /* Create first wallet */

    const wallet = {
      id: db.wallets.length + 1,
      userId,
      address: makeAddress(),
      balance: 0,
      createdAt: new Date().toISOString()
    };

    db.wallets.push(wallet);

    /* First block transaction */

    const tx = {
      id: makeId(),
      type: "CREATE_WALLET",
      userId,
      walletId: wallet.id,
      amount: 0,
      fee: 0,
      created_at: new Date().toISOString()
    };

    db.transactions.push(tx);

    createBlock([tx.id]);

    saveDatabase();

    const token = createToken(user);

    return res.status(201).json({
      ok: true,

      message: "Аккаунт успешно создан.",

      token,

      user: publicUser(user),

      wallet: publicWallet(wallet),

      recoveryCode
    });

  } catch (err) {

    console.error("REGISTER ERROR:", err);

    return res.status(500).json({
      ok: false,
      message:
        "Ошибка регистрации."
    });
  }
});

/* ============================================================
   LOGIN
============================================================ */

app.post("/api/auth/login", async (req, res) => {

  try {

    const username =
      String(req.body.username || "").trim();

    const password =
      String(req.body.password || "");

    if (!username || !password) {
      return res.status(400).json({
        ok: false,
        message:
          "Введите имя пользователя и пароль."
      });
    }

    const user =
      db.users.find(
        u =>
          u.username.toLowerCase() ===
          username.toLowerCase()
      );

    if (!user) {
      return res.status(401).json({
        ok: false,
        message:
          "Неверное имя пользователя или пароль."
      });
    }

    const valid =
      await bcrypt.compare(
        password,
        user.passwordHash
      );

    if (!valid) {
      return res.status(401).json({
        ok: false,
        message:
          "Неверное имя пользователя или пароль."
      });
    }

    const token =
      createToken(user);

    return res.json({
      ok: true,
      message: "Вход выполнен.",
      token,
      user: publicUser(user)
    });

  } catch (err) {

    console.error("LOGIN ERROR:", err);

    return res.status(500).json({
      ok: false,
      message:
        "Ошибка входа."
    });
  }
});

/* ============================================================
   ME
============================================================ */

app.get(
  "/api/auth/me",
  auth,
  (req, res) => {

    const wallets =
      db.wallets
        .filter(
          w => w.userId === req.user.id
        )
        .map(publicWallet);

    res.json({
      ok: true,
      user: publicUser(req.user),
      wallets
    });
  }
);

/* ============================================================
   LOGOUT
============================================================ */

app.post(
  "/api/auth/logout",
  auth,
  (req, res) => {

    res.json({
      ok: true,
      message: "Вы вышли из аккаунта."
    });
  }
);

/* ============================================================
   CREATE WALLET
============================================================ */

app.post(
  "/api/wallet/create",
  auth,
  (req, res) => {

    const wallet = {
      id: db.wallets.length + 1,
      userId: req.user.id,
      address: makeAddress(),
      balance: 0,
      createdAt: new Date().toISOString()
    };

    db.wallets.push(wallet);

    const tx = {
      id: makeId(),
      type: "CREATE_WALLET",
      userId: req.user.id,
      walletId: wallet.id,
      amount: 0,
      fee: 0,
      created_at: new Date().toISOString()
    };

    db.transactions.push(tx);

    createBlock([tx.id]);

    saveDatabase();

    res.status(201).json({
      ok: true,
      message: "Новый SLX Wallet создан.",
      wallet: publicWallet(wallet)
    });
  }
);

/* ============================================================
   SELECT WALLET
============================================================ */

app.post(
  "/api/wallet/select",
  auth,
  (req, res) => {

    const walletId =
      Number(req.body.walletId);

    const wallet =
      db.wallets.find(
        w =>
          Number(w.id) === walletId &&
          w.userId === req.user.id
      );

    if (!wallet) {
      return res.status(404).json({
        ok: false,
        message:
          "Кошелёк не найден."
      });
    }

    res.json({
      ok: true,
      wallet: publicWallet(wallet)
    });
  }
);

/* ============================================================
   WALLET
============================================================ */

app.get(
  "/api/wallet/:id",
  auth,
  (req, res) => {

    const walletId =
      Number(req.params.id);

    const wallet =
      db.wallets.find(
        w =>
          Number(w.id) === walletId &&
          w.userId === req.user.id
      );

    if (!wallet) {
      return res.status(404).json({
        ok: false,
        message:
          "Кошелёк не найден."
      });
    }

    const transactions =
      db.transactions.filter(
        tx =>
          Number(tx.walletId) ===
          Number(wallet.id)
      );

    res.json({
      ok: true,

      wallet: {
        ...publicWallet(wallet),
        transactions
      }
    });
  }
);

/* ============================================================
   SEND SLX
============================================================ */

app.post(
  "/api/send",
  auth,
  (req, res) => {

    const from =
      String(req.body.from || "")
        .trim()
        .toUpperCase();

    const to =
      String(req.body.to || "")
        .trim()
        .toUpperCase();

    const amount =
      Number(req.body.amount);

    const FEE = 0.1;

    if (
      !/^SLXC[A-F0-9]{32}$/.test(from)
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Некорректный адрес отправителя."
      });
    }

    if (
      !/^SLXC[A-F0-9]{32}$/.test(to)
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Некорректный адрес получателя."
      });
    }

    if (
      !Number.isFinite(amount) ||
      amount <= 0
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Некорректная сумма."
      });
    }

    if (from === to) {
      return res.status(400).json({
        ok: false,
        message:
          "Нельзя отправить самому себе."
      });
    }

    const sender =
      db.wallets.find(
        w =>
          w.address === from &&
          w.userId === req.user.id
      );

    if (!sender) {
      return res.status(403).json({
        ok: false,
        message:
          "Кошелёк отправителя вам не принадлежит."
      });
    }

    const receiver =
      db.wallets.find(
        w => w.address === to
      );

    if (!receiver) {
      return res.status(404).json({
        ok: false,
        message:
          "Кошелёк получателя не найден."
      });
    }

    const total =
      roundSLX(amount + FEE);

    if (
      Number(sender.balance) < total
    ) {
      return res.status(400).json({
        ok: false,
        message:
          `Недостаточно SLX. Нужно ${total} SLX.`
      });
    }

    sender.balance =
      roundSLX(
        Number(sender.balance) -
        total
      );

    receiver.balance =
      roundSLX(
        Number(receiver.balance) +
        amount
      );

    const sendTx = {
      id: makeId(),
      type: "SEND",
      userId: req.user.id,
      walletId: sender.id,
      from,
      to,
      amount: roundSLX(amount),
      fee: FEE,
      created_at:
        new Date().toISOString()
    };

    const receiveTx = {
      id: makeId(),
      type: "RECEIVE",
      userId: receiver.userId,
      walletId: receiver.id,
      from,
      to,
      amount: roundSLX(amount),
      fee: 0,
      created_at:
        new Date().toISOString()
    };

    db.transactions.push(sendTx);
    db.transactions.push(receiveTx);

    createBlock([
      sendTx.id,
      receiveTx.id
    ]);

    saveDatabase();

    res.json({
      ok: true,
      message: "Транзакция выполнена.",
      amount: roundSLX(amount),
      fee: FEE,
      transactionId: sendTx.id
    });
  }
);

/* ============================================================
   FAUCET
============================================================ */

app.post(
  "/api/faucet",
  auth,
  (req, res) => {

    const walletId =
      Number(req.body.walletId);

    const wallet =
      db.wallets.find(
        w =>
          Number(w.id) === walletId &&
          w.userId === req.user.id
      );

    if (!wallet) {
      return res.status(404).json({
        ok: false,
        message:
          "Кошелёк не найден."
      });
    }

    const lastFaucet =
      db.transactions
        .filter(
          tx =>
            tx.type === "FAUCET" &&
            tx.walletId === wallet.id
        )
        .sort(
          (a, b) =>
            new Date(b.created_at) -
            new Date(a.created_at)
        )[0];

    if (lastFaucet) {

      const elapsed =
        Date.now() -
        new Date(
          lastFaucet.created_at
        ).getTime();

      const day =
        24 * 60 * 60 * 1000;

      if (elapsed < day) {

        const remaining =
          Math.ceil(
            (day - elapsed) /
            3600000
          );

        return res.status(429).json({
          ok: false,
          message:
            `Faucet уже использован. Попробуйте примерно через ${remaining} ч.`
        });
      }
    }

    const amount = 10;

    wallet.balance =
      roundSLX(
        Number(wallet.balance) +
        amount
      );

    const tx = {
      id: makeId(),
      type: "FAUCET",
      userId: req.user.id,
      walletId: wallet.id,
      amount,
      fee: 0,
      created_at:
        new Date().toISOString()
    };

    db.transactions.push(tx);

    createBlock([tx.id]);

    saveDatabase();

    res.json({
      ok: true,
      message:
        "Получено +10 SLX.",
      amount,
      wallet:
        publicWallet(wallet)
    });
  }
);

/* ============================================================
   RECOVERY RESET
============================================================ */

app.post(
  "/api/auth/recovery/reset",
  async (req, res) => {

    try {

      const username =
        String(
          req.body.username || ""
        ).trim();

      const recoveryCode =
        String(
          req.body.recoveryCode || ""
        ).trim();

      const newPassword =
        String(
          req.body.newPassword || ""
        );

      if (
        !username ||
        !recoveryCode ||
        !newPassword
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "Заполните все поля."
        });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({
          ok: false,
          message:
            "Новый пароль должен содержать минимум 6 символов."
        });
      }

      const user =
        db.users.find(
          u =>
            u.username.toLowerCase() ===
            username.toLowerCase()
        );

      if (!user) {
        return res.status(400).json({
          ok: false,
          message:
            "Неверные данные восстановления."
        });
      }

      const valid =
        await bcrypt.compare(
          recoveryCode,
          user.recoveryHash
        );

      if (!valid) {
        return res.status(400).json({
          ok: false,
          message:
            "Неверный Recovery Code."
        });
      }

      user.passwordHash =
        await bcrypt.hash(
          newPassword,
          12
        );

      saveDatabase();

      const token =
        createToken(user);

      res.json({
        ok: true,
        message:
          "Пароль успешно восстановлен.",
        token
      });

    } catch (err) {

      console.error(
        "RECOVERY ERROR:",
        err
      );

      res.status(500).json({
        ok: false,
        message:
          "Ошибка восстановления."
      });
    }
  }
);

/* ============================================================
   CHANGE PASSWORD
============================================================ */

app.post(
  "/api/auth/password/change",
  auth,
  async (req, res) => {

    try {

      const oldPassword =
        String(
          req.body.oldPassword || ""
        );

      const newPassword =
        String(
          req.body.newPassword || ""
        );

      if (
        !oldPassword ||
        !newPassword
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "Заполните оба поля."
        });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({
          ok: false,
          message:
            "Новый пароль должен содержать минимум 6 символов."
        });
      }

      const valid =
        await bcrypt.compare(
          oldPassword,
          req.user.passwordHash
        );

      if (!valid) {
        return res.status(400).json({
          ok: false,
          message:
            "Старый пароль указан неправильно."
        });
      }

      req.user.passwordHash =
        await bcrypt.hash(
          newPassword,
          12
        );

      saveDatabase();

      const token =
        createToken(req.user);

      res.json({
        ok: true,
        message:
          "Пароль изменён.",
        token
      });

    } catch (err) {

      console.error(
        "PASSWORD ERROR:",
        err
      );

      res.status(500).json({
        ok: false,
        message:
          "Ошибка изменения пароля."
      });
    }
  }
);

/* ============================================================
   VERIFY BLOCKCHAIN
============================================================ */

app.get(
  "/api/chain/verify",
  auth,
  (req, res) => {

    for (
      let i = 0;
      i < db.blocks.length;
      i++
    ) {

      const block =
        db.blocks[i];

      const expected =
        calculateBlockHash(block);

      if (block.hash !== expected) {

        return res.json({
          ok: true,
          valid: false,
          message:
            `Ошибка целостности блока ${block.index}.`,
          blocks:
            db.blocks.length
        });
      }

      if (i > 0) {

        const previous =
          db.blocks[i - 1];

        if (
          block.previousHash !==
          previous.hash
        ) {

          return res.json({
            ok: true,
            valid: false,
            message:
              `Нарушена связь блока ${block.index}.`,
            blocks:
              db.blocks.length
          });
        }
      }
    }

    res.json({
      ok: true,
      valid: true,
      message:
        "Blockchain полностью валиден.",
      blocks:
        db.blocks.length
    });
  }
);

/* ============================================================
   404 API
============================================================ */

app.use("/api", (req, res) => {

  res.status(404).json({
    ok: false,
    message:
      "API endpoint не найден."
  });
});

/* ============================================================
   ERROR HANDLER
============================================================ */

app.use((err, req, res, next) => {

  console.error("SERVER ERROR:", err);

  res.status(500).json({
    ok: false,
    message:
      "Внутренняя ошибка сервера."
  });
});

/* ============================================================
   START
============================================================ */

app.listen(PORT, () => {

  console.log(
    "========================================"
  );

  console.log(
    "SLX Network v1.9.0"
  );

  console.log(
    "Network: SLX-TESTNET-1"
  );

  console.log(
    "Status: ONLINE"
  );

  console.log(
    `Port: ${PORT}`
  );

  console.log(
    `Users: ${db.users.length}`
  );

  console.log(
    `Wallets: ${db.wallets.length}`
  );

  console.log(
    `Blocks: ${db.blocks.length}`
  );

  console.log(
    "========================================"
  );
});