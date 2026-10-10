const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

/* =========================================================
   CONFIG
   ========================================================= */

const PORT = process.env.PORT || 10000;
const HOST = "0.0.0.0";

const VERSION = "1.9.0";
const NETWORK = "SLX-Testnet";

const TRANSFER_FEE = 0.1;
const FAUCET_AMOUNT = 10;

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "SLX_NETWORK_TESTNET_SECRET_2026_CHANGE_ME";

const DATA_DIR =
  process.env.SLX_DATA_DIR ||
  path.join(__dirname, "data");

const DATA_FILE =
  path.join(DATA_DIR, "slx-data.json");

const PUBLIC_DIR =
  path.join(__dirname, "public");

const INDEX_FILE =
  path.join(PUBLIC_DIR, "index.html");


/* =========================================================
   EXPRESS
   ========================================================= */

app.use(
  express.json({
    limit: "2mb"
  })
);

app.use(
  express.urlencoded({
    extended: true
  })
);


/* =========================================================
   DATABASE
   ========================================================= */

function ensureDatabase() {

  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, {
      recursive: true
    });
  }

  if (!fs.existsSync(DATA_FILE)) {

    const database = {
      users: [],
      wallets: [],
      transactions: [],
      blocks: [],

      network: {
        version: VERSION,
        name: NETWORK,
        height: 0,
        totalSupply: 0,
        genesisTime: Date.now()
      }
    };

    fs.writeFileSync(
      DATA_FILE,
      JSON.stringify(database, null, 2),
      "utf8"
    );
  }
}

ensureDatabase();


function loadDatabase() {

  try {

    const data =
      fs.readFileSync(
        DATA_FILE,
        "utf8"
      );

    const database =
      JSON.parse(data);

    database.users ||= [];
    database.wallets ||= [];
    database.transactions ||= [];
    database.blocks ||= [];

    database.network ||= {
      version: VERSION,
      name: NETWORK,
      height: 0,
      totalSupply: 0,
      genesisTime: Date.now()
    };

    return database;

  } catch (error) {

    console.error(
      "DATABASE ERROR:",
      error
    );

    return {
      users: [],
      wallets: [],
      transactions: [],
      blocks: [],

      network: {
        version: VERSION,
        name: NETWORK,
        height: 0,
        totalSupply: 0,
        genesisTime: Date.now()
      }
    };
  }
}


let db = loadDatabase();


function saveDatabase() {

  fs.writeFileSync(
    DATA_FILE,
    JSON.stringify(db, null, 2),
    "utf8"
  );
}


/* =========================================================
   HELPERS
   ========================================================= */

function makeId(prefix = "") {

  return (
    prefix +
    crypto
      .randomBytes(12)
      .toString("hex")
  );
}


function makeWalletAddress() {

  return (
    "SLXC" +
    crypto
      .randomBytes(16)
      .toString("hex")
      .toUpperCase()
  );
}


function timestamp() {

  return new Date().toISOString();
}


function toNumber(value) {

  const number =
    Number(value);

  if (!Number.isFinite(number)) {
    return 0;
  }

  return number;
}


function round(value) {

  return Math.round(
    Number(value) * 1000000
  ) / 1000000;
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

    balance:
      round(wallet.balance),

    amount:
      round(wallet.balance),

    createdAt:
      wallet.createdAt
  };
}


function getUserWallets(userId) {

  return db.wallets.filter(
    wallet =>
      wallet.userId === userId
  );
}


function getWallet(
  userId,
  walletId
) {

  return db.wallets.find(
    wallet =>
      wallet.userId === userId &&
      String(wallet.id) ===
      String(walletId)
  );
}


function getWalletByAddress(address) {

  const target =
    String(address)
      .trim()
      .toUpperCase();

  return db.wallets.find(
    wallet =>
      String(wallet.address)
        .toUpperCase() === target
  );
}


/* =========================================================
   JWT
   ========================================================= */

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

  const header =
    req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {

    return res.status(401).json({
      error: "Требуется авторизация"
    });
  }

  const token =
    header.substring(7);

  try {

    const decoded =
      jwt.verify(
        token,
        JWT_SECRET
      );

    const user =
      db.users.find(
        item =>
          item.id === decoded.userId
      );

    if (!user) {

      return res.status(401).json({
        error: "Пользователь не найден"
      });
    }

    req.user = user;

    next();

  } catch (error) {

    return res.status(401).json({
      error: "Сессия недействительна"
    });
  }
}


/* =========================================================
   WALLET
   ========================================================= */

function createWalletForUser(
  userId,
  firstWallet = false
) {

  let address;

  do {

    address =
      makeWalletAddress();

  } while (
    getWalletByAddress(address)
  );


  const wallet = {

    id:
      makeId("WLT_")
        .toUpperCase(),

    userId,

    address,

    balance:
      firstWallet ? 100 : 0,

    createdAt:
      timestamp()
  };


  db.wallets.push(wallet);


  /*
   * Первый тестовый кошелёк получает
   * стартовые 100 SLX.
   */

  if (firstWallet) {

    db.network.totalSupply =
      round(
        db.network.totalSupply +
        100
      );

    addTransaction({

      type: "genesis",

      from:
        "SLX_GENESIS",

      to:
        wallet.address,

      amount: 100,

      fee: 0,

      walletId:
        wallet.id,

      userId
    });
  }


  return wallet;
}


/* =========================================================
   TRANSACTIONS
   ========================================================= */

function addTransaction(data) {

  const transaction = {

    id:
      makeId("tx_"),

    hash:
      crypto
        .createHash("sha256")
        .update(
          JSON.stringify({
            data,
            time: Date.now(),
            random:
              crypto
                .randomBytes(8)
                .toString("hex")
          })
        )
        .digest("hex"),

    type:
      data.type || "transfer",

    from:
      data.from || null,

    to:
      data.to || null,

    amount:
      round(data.amount || 0),

    fee:
      round(data.fee || 0),

    walletId:
      data.walletId || null,

    userId:
      data.userId || null,

    status:
      "confirmed",

    createdAt:
      timestamp()
  };


  db.transactions.push(
    transaction
  );


  return transaction;
}


/* =========================================================
   BLOCKCHAIN
   ========================================================= */

function calculateBlockHash(block) {

  return crypto
    .createHash("sha256")
    .update(
      JSON.stringify({
        index: block.index,
        previousHash:
          block.previousHash,
        transactions:
          block.transactions,
        timestamp:
          block.timestamp
      })
    )
    .digest("hex");
}


function createBlock(transaction) {

  const previous =
    db.blocks[
      db.blocks.length - 1
    ];


  const block = {

    index:
      db.blocks.length,

    height:
      db.blocks.length,

    previousHash:
      previous
        ? previous.hash
        : "0".repeat(64),

    transactions: [
      transaction
    ],

    timestamp:
      Date.now(),

    hash: ""
  };


  block.hash =
    calculateBlockHash(
      block
    );


  db.blocks.push(
    block
  );


  db.network.height =
    db.blocks.length;


  return block;
}


/* =========================================================
   HOME
   ========================================================= */

app.get("/", (req, res) => {

  if (fs.existsSync(INDEX_FILE)) {

    return res.sendFile(
      INDEX_FILE
    );
  }


  return res.status(503).send(`
    <!doctype html>
    <html lang="ru">
    <head>
      <meta charset="utf-8">
      <meta name="viewport"
            content="width=device-width,initial-scale=1">
      <title>SLX Network</title>
    </head>

    <body style="
      background:#080b12;
      color:white;
      font-family:Arial;
      padding:40px;
    ">

      <h1>SLX Network</h1>

      <p>
        Сервер работает.
      </p>

      <p>
        Но файл
        <b>public/index.html</b>
        пока не найден.
      </p>

    </body>
    </html>
  `);
});


/* =========================================================
   STATIC FRONTEND
   ========================================================= */

if (fs.existsSync(PUBLIC_DIR)) {

  app.use(
    express.static(
      PUBLIC_DIR
    )
  );
}


/* =========================================================
   HEALTH
   ========================================================= */

app.get(
  "/api/health",
  (req, res) => {

    res.json({

      ok: true,

      name:
        "SLX Network",

      version:
        VERSION,

      network:
        NETWORK,

      status:
        "online"
    });
  }
);


/* =========================================================
   STATUS
   ========================================================= */

app.get(
  "/api/status",
  (req, res) => {

    res.json({

      ok: true,

      status:
        "online",

      name:
        "SLX Network",

      version:
        VERSION,

      network:
        NETWORK,

      networkVersion:
        VERSION,

      transferFee:
        TRANSFER_FEE,

      fee:
        TRANSFER_FEE,

      faucet:
        FAUCET_AMOUNT,

      height:
        db.blocks.length,

      blocks:
        db.blocks.length,

      users:
        db.users.length,

      wallets:
        db.wallets.length,

      transactions:
        db.transactions.length,

      totalSupply:
        round(
          db.network.totalSupply
        ),

      uptime:
        process.uptime(),

      timestamp:
        timestamp()
    });
  }
);


/* =========================================================
   REGISTER
   ========================================================= */

app.post(
  "/api/auth/register",
  async (req, res) => {

    try {

      const username =
        String(
          req.body.username || ""
        ).trim();

      const password =
        String(
          req.body.password || ""
        );


      if (username.length < 3) {

        return res.status(400).json({
          error:
            "Логин должен содержать минимум 3 символа"
        });
      }


      if (password.length < 6) {

        return res.status(400).json({
          error:
            "Пароль должен содержать минимум 6 символов"
        });
      }


      const exists =
        db.users.find(
          user =>
            user.username
              .toLowerCase() ===
            username.toLowerCase()
        );


      if (exists) {

        return res.status(409).json({
          error:
            "Такой пользователь уже существует"
        });
      }


      const user = {

        id:
          makeId("usr_"),

        username,

        passwordHash:
          await bcrypt.hash(
            password,
            12
          ),

        createdAt:
          timestamp(),

        activeWalletId:
          null
      };


      db.users.push(
        user
      );


      const wallet =
        createWalletForUser(
          user.id,
          true
        );


      user.activeWalletId =
        wallet.id;


      saveDatabase();


      const token =
        createToken(user);


      res.json({

        ok: true,

        token,

        user:
          publicUser(user),

        wallet:
          publicWallet(wallet)
      });


    } catch (error) {

      console.error(
        "REGISTER ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Ошибка регистрации"
      });
    }
  }
);


/* =========================================================
   LOGIN
   ========================================================= */

app.post(
  "/api/auth/login",
  async (req, res) => {

    try {

      const username =
        String(
          req.body.username || ""
        ).trim();

      const password =
        String(
          req.body.password || ""
        );


      const user =
        db.users.find(
          item =>
            item.username
              .toLowerCase() ===
            username.toLowerCase()
        );


      if (!user) {

        return res.status(401).json({
          error:
            "Неверный логин или пароль"
        });
      }


      const valid =
        await bcrypt.compare(
          password,
          user.passwordHash
        );


      if (!valid) {

        return res.status(401).json({
          error:
            "Неверный логин или пароль"
        });
      }


      const token =
        createToken(user);


      res.json({

        ok: true,

        token,

        user:
          publicUser(user)
      });


    } catch (error) {

      console.error(
        "LOGIN ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Ошибка входа"
      });
    }
  }
);


/* =========================================================
   ME
   ========================================================= */

app.get(
  "/api/auth/me",
  auth,
  (req, res) => {

    res.json({

      ok: true,

      user:
        publicUser(
          req.user
        )
    });
  }
);


/* =========================================================
   LOGOUT
   ========================================================= */

app.post(
  "/api/auth/logout",
  auth,
  (req, res) => {

    res.json({
      ok: true,
      message:
        "Выход выполнен"
    });
  }
);


/* =========================================================
   CHANGE PASSWORD
   ========================================================= */

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


      if (newPassword.length < 6) {

        return res.status(400).json({
          error:
            "Новый пароль должен содержать минимум 6 символов"
        });
      }


      const valid =
        await bcrypt.compare(
          oldPassword,
          req.user.passwordHash
        );


      if (!valid) {

        return res.status(400).json({
          error:
            "Старый пароль указан неверно"
        });
      }


      req.user.passwordHash =
        await bcrypt.hash(
          newPassword,
          12
        );


      saveDatabase();


      res.json({

        ok: true,

        message:
          "Пароль успешно изменён"
      });


    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Ошибка смены пароля"
      });
    }
  }
);


/* =========================================================
   RECOVERY
   ========================================================= */

app.post(
  "/api/auth/recovery/reset",
  async (req, res) => {

    try {

      const username =
        String(
          req.body.username || ""
        ).trim();

      const newPassword =
        String(
          req.body.newPassword ||
          req.body.password ||
          ""
        );


      if (
        !username ||
        !newPassword
      ) {

        return res.status(400).json({
          error:
            "Недостаточно данных"
        });
      }


      if (newPassword.length < 6) {

        return res.status(400).json({
          error:
            "Пароль должен содержать минимум 6 символов"
        });
      }


      const user =
        db.users.find(
          item =>
            item.username
              .toLowerCase() ===
            username.toLowerCase()
        );


      if (!user) {

        return res.status(404).json({
          error:
            "Пользователь не найден"
        });
      }


      user.passwordHash =
        await bcrypt.hash(
          newPassword,
          12
        );


      saveDatabase();


      res.json({

        ok: true,

        message:
          "Пароль сброшен"
      });


    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Ошибка восстановления"
      });
    }
  }
);


/* =========================================================
   WALLETS
   ========================================================= */

app.get(
  "/api/wallets",
  auth,
  (req, res) => {

    const wallets =
      getUserWallets(
        req.user.id
      );


    const result =
      wallets.map(
        publicWallet
      );


    res.json({

      ok: true,

      wallets:
        result,

      data:
        result
    });
  }
);


/* =========================================================
   CREATE WALLET
   ========================================================= */

app.post(
  "/api/wallet/create",
  auth,
  (req, res) => {

    try {

      const wallet =
        createWalletForUser(
          req.user.id,
          false
        );


      if (!req.user.activeWalletId) {

        req.user.activeWalletId =
          wallet.id;
      }


      saveDatabase();


      res.json({

        ok: true,

        wallet:
          publicWallet(wallet)
      });


    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Не удалось создать кошелёк"
      });
    }
  }
);


/* =========================================================
   SELECT WALLET
   ========================================================= */

app.post(
  "/api/wallet/select",
  auth,
  (req, res) => {

    const walletId =
      req.body.walletId ||
      req.body.id;


    const wallet =
      getWallet(
        req.user.id,
        walletId
      );


    if (!wallet) {

      return res.status(404).json({
        error:
          "Кошелёк не найден"
      });
    }


    req.user.activeWalletId =
      wallet.id;


    saveDatabase();


    res.json({

      ok: true,

      wallet:
        publicWallet(wallet)
    });
  }
);


/* =========================================================
   SINGLE WALLET
   ========================================================= */

app.get(
  "/api/wallet/:id",
  auth,
  (req, res) => {

    const wallet =
      getWallet(
        req.user.id,
        req.params.id
      );


    if (!wallet) {

      return res.status(404).json({
        error:
          "Кошелёк не найден"
      });
    }


    res.json({

      ok: true,

      wallet:
        publicWallet(wallet)
    });
  }
);


/* =========================================================
   SEND SLX
   ========================================================= */

app.post(
  "/api/send",
  auth,
  (req, res) => {

    try {

      const to =
        String(
          req.body.to || ""
        )
        .trim()
        .toUpperCase();


      const amount =
        round(
          toNumber(
            req.body.amount
          )
        );


      if (
        !/^SLXC[A-F0-9]{32}$/.test(to)
      ) {

        return res.status(400).json({
          error:
            "Неверный адрес SLX"
        });
      }


      if (amount <= 0) {

        return res.status(400).json({
          error:
            "Сумма должна быть больше 0"
        });
      }


      const sender =
        getWallet(
          req.user.id,
          req.user.activeWalletId
        );


      if (!sender) {

        return res.status(400).json({
          error:
            "Активный кошелёк не найден"
        });
      }


      const recipient =
        getWalletByAddress(to);


      if (!recipient) {

        return res.status(404).json({
          error:
            "Кошелёк получателя не найден в тестовой сети"
        });
      }


      if (
        recipient.id ===
        sender.id
      ) {

        return res.status(400).json({
          error:
            "Нельзя отправить самому себе"
        });
      }


      const fee =
        TRANSFER_FEE;


      const total =
        round(
          amount + fee
        );


      if (
        sender.balance <
        total
      ) {

        return res.status(400).json({
          error:
            `Недостаточно SLX. Нужно ${total} SLX`
        });
      }


      sender.balance =
        round(
          sender.balance -
          total
        );


      recipient.balance =
        round(
          recipient.balance +
          amount
        );


      const transaction =
        addTransaction({

          type:
            "transfer",

          from:
            sender.address,

          to:
            recipient.address,

          amount,

          fee,

          walletId:
            sender.id,

          userId:
            req.user.id
        });


      createBlock(
        transaction
      );


      saveDatabase();


      res.json({

        ok: true,

        transaction,

        tx:
          transaction,

        fee,

        balance:
          sender.balance
      });


    } catch (error) {

      console.error(
        "SEND ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Ошибка отправки SLX"
      });
    }
  }
);


/* =========================================================
   FAUCET
   ========================================================= */

app.post(
  "/api/faucet",
  auth,
  (req, res) => {

    try {

      const walletId =
        req.body.walletId ||
        req.body.id ||
        req.user.activeWalletId;


      const wallet =
        getWallet(
          req.user.id,
          walletId
        );


      if (!wallet) {

        return res.status(404).json({
          error:
            "Кошелёк не найден"
        });
      }


      wallet.balance =
        round(
          wallet.balance +
          FAUCET_AMOUNT
        );


      db.network.totalSupply =
        round(
          db.network.totalSupply +
          FAUCET_AMOUNT
        );


      const transaction =
        addTransaction({

          type:
            "faucet",

          from:
            "SLX_FAUCET",

          to:
            wallet.address,

          amount:
            FAUCET_AMOUNT,

          fee:
            0,

          walletId:
            wallet.id,

          userId:
            req.user.id
        });


      createBlock(
        transaction
      );


      saveDatabase();


      res.json({

        ok: true,

        amount:
          FAUCET_AMOUNT,

        wallet:
          publicWallet(wallet),

        transaction
      });


    } catch (error) {

      console.error(
        "FAUCET ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Ошибка faucet"
      });
    }
  }
);


/* =========================================================
   HISTORY
   ========================================================= */

function getUserTransactions(
  userId
) {

  const wallets =
    getUserWallets(
      userId
    );


  const addresses =
    new Set(
      wallets.map(
        wallet =>
          wallet.address.toUpperCase()
      )
    );


  return db.transactions
    .filter(transaction => {

      const from =
        String(
          transaction.from || ""
        ).toUpperCase();

      const to =
        String(
          transaction.to || ""
        ).toUpperCase();

      return (
        addresses.has(from) ||
        addresses.has(to)
      );
    })
    .reverse();
}


app.get(
  "/api/transactions",
  auth,
  (req, res) => {

    const transactions =
      getUserTransactions(
        req.user.id
      );


    res.json({

      ok: true,

      transactions,

      data:
        transactions
    });
  }
);


app.get(
  "/api/history",
  auth,
  (req, res) => {

    const history =
      getUserTransactions(
        req.user.id
      );


    res.json({

      ok: true,

      history,

      transactions:
        history,

      data:
        history
    });
  }
);


/* =========================================================
   BLOCKS
   ========================================================= */

app.get(
  "/api/blocks",
  (req, res) => {

    let limit =
      Number(
        req.query.limit
      ) || 20;


    limit =
      Math.max(
        1,
        Math.min(
          limit,
          100
        )
      );


    const blocks =
      db.blocks
        .slice(-limit)
        .reverse();


    res.json({

      ok: true,

      blocks,

      count:
        db.blocks.length,

      height:
        db.blocks.length,

      data:
        blocks
    });
  }
);


/* =========================================================
   ECONOMY
   ========================================================= */

app.get(
  "/api/economy",
  (req, res) => {

    const circulating =
      db.wallets.reduce(
        (
          total,
          wallet
        ) =>
          total +
          toNumber(
            wallet.balance
          ),
        0
      );


    res.json({

      ok: true,

      network:
        NETWORK,

      version:
        VERSION,

      totalSupply:
        round(
          db.network.totalSupply
        ),

      circulatingSupply:
        round(
          circulating
        ),

      users:
        db.users.length,

      wallets:
        db.wallets.length,

      transactions:
        db.transactions.length,

      blocks:
        db.blocks.length,

      transferFee:
        TRANSFER_FEE,

      faucetAmount:
        FAUCET_AMOUNT
    });
  }
);


/* =========================================================
   VERIFY BLOCKCHAIN
   ========================================================= */

app.get(
  "/api/chain/verify",
  (req, res) => {

    let valid = true;
    let error = null;


    for (
      let i = 0;
      i < db.blocks.length;
      i++
    ) {

      const block =
        db.blocks[i];


      const previousHash =
        i === 0
          ? "0".repeat(64)
          : db.blocks[i - 1].hash;


      if (
        block.previousHash !==
        previousHash
      ) {

        valid = false;

        error =
          `Ошибка previousHash в блоке ${i}`;

        break;
      }


      const calculatedHash =
        calculateBlockHash(
          block
        );


      if (
        block.hash !==
        calculatedHash
      ) {

        valid = false;

        error =
          `Ошибка hash в блоке ${i}`;

        break;
      }
    }


    res.json({

      ok:
        valid,

      valid,

      verified:
        valid,

      blocks:
        db.blocks.length,

      error
    });
  }
);


/* =========================================================
   DEBUG
   ========================================================= */

app.get(
  "/api/debug",
  auth,
  (req, res) => {

    res.json({

      ok: true,

      version:
        VERSION,

      network:
        NETWORK,

      user:
        publicUser(
          req.user
        ),

      wallets:
        getUserWallets(
          req.user.id
        ).map(
          publicWallet
        ),

      database: {

        users:
          db.users.length,

        wallets:
          db.wallets.length,

        transactions:
          db.transactions.length,

        blocks:
          db.blocks.length
      }
    });
  }
);


/* =========================================================
   API 404
   ========================================================= */

app.use(
  "/api",
  (req, res) => {

    res.status(404).json({

      ok: false,

      error:
        "API endpoint не найден",

      path:
        req.path
    });
  }
);


/* =========================================================
   FRONTEND FALLBACK
   ========================================================= */

app.get(
  "*",
  (req, res) => {

    if (
      fs.existsSync(INDEX_FILE)
    ) {

      return res.sendFile(
        INDEX_FILE
      );
    }


    res.status(404).send(
      "SLX Network frontend not found"
    );
  }
);


/* =========================================================
   ERROR HANDLER
   ========================================================= */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {

    console.error(
      "SERVER ERROR:",
      error
    );


    if (
      res.headersSent
    ) {
      return next(error);
    }


    res.status(500).json({

      ok: false,

      error:
        "Внутренняя ошибка сервера"
    });
  }
);


/* =========================================================
   START SERVER
   ========================================================= */

app.listen(
  PORT,
  HOST,
  () => {

    console.log("");
    console.log(
      "======================================"
    );

    console.log(
      "          SLX NETWORK"
    );

    console.log(
      "======================================"
    );

    console.log(
      "Version:",
      VERSION
    );

    console.log(
      "Network:",
      NETWORK
    );

    console.log(
      "Status: ONLINE"
    );

    console.log(
      "Port:",
      PORT
    );

    console.log(
      "Frontend:",
      fs.existsSync(INDEX_FILE)
        ? "FOUND"
        : "NOT FOUND"
    );

    console.log(
      "Database:",
      DATA_FILE
    );

    console.log(
      "======================================"
    );

    console.log("");
  }
);