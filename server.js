const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

const PORT = process.env.PORT || 10000;
const HOST = "0.0.0.0";

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "SLX_TESTNET_SECRET_CHANGE_ME_2026";

const DATA_DIR =
  process.env.SLX_DATA_DIR ||
  path.join(__dirname, "data");

const DATA_FILE =
  path.join(DATA_DIR, "slx-data.json");

const VERSION = "1.9.0";
const NETWORK = "SLX-Testnet";

const TRANSFER_FEE = 0.1;
const FAUCET_AMOUNT = 10;

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

/* =========================================================
   DATABASE
   ========================================================= */

function ensureData(){

  if(!fs.existsSync(DATA_DIR)){
    fs.mkdirSync(DATA_DIR, {
      recursive: true
    });
  }

  if(!fs.existsSync(DATA_FILE)){

    const initial = {
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
      JSON.stringify(initial, null, 2)
    );
  }
}

ensureData();

function loadDB(){

  try{

    const raw =
      fs.readFileSync(
        DATA_FILE,
        "utf8"
      );

    const db =
      JSON.parse(raw);

    db.users ||= [];
    db.wallets ||= [];
    db.transactions ||= [];
    db.blocks ||= [];

    db.network ||= {
      version: VERSION,
      name: NETWORK,
      height: 0,
      totalSupply: 0,
      genesisTime: Date.now()
    };

    return db;

  }catch(error){

    console.error(
      "DATABASE LOAD ERROR:",
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

let db = loadDB();

function saveDB(){

  fs.writeFileSync(
    DATA_FILE,
    JSON.stringify(db, null, 2)
  );
}


/* =========================================================
   HELPERS
   ========================================================= */

function id(prefix = ""){

  return (
    prefix +
    crypto.randomBytes(12).toString("hex")
  );
}

function walletAddress(){

  return (
    "SLXC" +
    crypto
      .randomBytes(16)
      .toString("hex")
      .toUpperCase()
  );
}

function now(){

  return new Date().toISOString();
}

function number(value){

  const n = Number(value);

  return Number.isFinite(n)
    ? n
    : 0;
}

function round(value){

  return Math.round(
    Number(value) * 1000000
  ) / 1000000;
}

function publicUser(user){

  return {
    id: user.id,
    username: user.username,
    createdAt: user.createdAt
  };
}

function publicWallet(wallet){

  return {
    id: wallet.id,
    address: wallet.address,
    balance: round(wallet.balance),
    amount: round(wallet.balance),
    createdAt: wallet.createdAt
  };
}

function getUserWallets(userId){

  return db.wallets.filter(
    wallet =>
      wallet.userId === userId
  );
}

function getWallet(
  userId,
  walletId
){

  return db.wallets.find(
    wallet =>
      wallet.userId === userId &&
      String(wallet.id) === String(walletId)
  );
}

function getWalletByAddress(address){

  return db.wallets.find(
    wallet =>
      String(wallet.address).toUpperCase() ===
      String(address).toUpperCase()
  );
}


/* =========================================================
   AUTH
   ========================================================= */

function createToken(user){

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

function auth(req,res,next){

  const header =
    req.headers.authorization || "";

  if(!header.startsWith("Bearer ")){

    return res.status(401).json({
      error: "Требуется авторизация"
    });
  }

  const token =
    header.substring(7);

  try{

    const decoded =
      jwt.verify(
        token,
        JWT_SECRET
      );

    const user =
      db.users.find(
        u => u.id === decoded.userId
      );

    if(!user){

      return res.status(401).json({
        error: "Пользователь не найден"
      });
    }

    req.user = user;

    next();

  }catch{

    return res.status(401).json({
      error: "Недействительная сессия"
    });
  }
}


/* =========================================================
   HEALTH
   ========================================================= */

app.get("/", (req,res)=>{

  res.json({
    name: "SLX Network",
    version: VERSION,
    network: NETWORK,
    status: "online",
    message: "SLX Network server is running"
  });
});

app.get("/api/health", (req,res)=>{

  res.json({
    ok: true,
    status: "online",
    version: VERSION,
    network: NETWORK
  });
});


/* =========================================================
   REGISTER
   ========================================================= */

app.post(
  "/api/auth/register",
  async (req,res)=>{

    try{

      const username =
        String(
          req.body.username || ""
        ).trim();

      const password =
        String(
          req.body.password || ""
        );

      if(username.length < 3){

        return res.status(400).json({
          error:
            "Логин должен содержать минимум 3 символа"
        });
      }

      if(password.length < 6){

        return res.status(400).json({
          error:
            "Пароль должен содержать минимум 6 символов"
        });
      }

      const exists =
        db.users.find(
          user =>
            user.username.toLowerCase() ===
            username.toLowerCase()
        );

      if(exists){

        return res.status(409).json({
          error:
            "Такой пользователь уже существует"
        });
      }

      const user = {
        id: id("usr_"),
        username,
        passwordHash:
          await bcrypt.hash(
            password,
            12
          ),
        createdAt: now(),
        activeWalletId: null
      };

      db.users.push(user);

      const wallet = createWalletForUser(
        user.id,
        true
      );

      user.activeWalletId =
        wallet.id;

      saveDB();

      const token =
        createToken(user);

      res.json({
        ok: true,
        token,
        user: publicUser(user),
        wallet: publicWallet(wallet)
      });

    }catch(error){

      console.error(error);

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
  async (req,res)=>{

    try{

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
          u =>
            u.username.toLowerCase() ===
            username.toLowerCase()
        );

      if(!user){

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

      if(!valid){

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
        user: publicUser(user)
      });

    }catch(error){

      console.error(error);

      res.status(500).json({
        error:
          "Ошибка входа"
      });
    }
  }
);


/* =========================================================
   CURRENT USER
   ========================================================= */

app.get(
  "/api/auth/me",
  auth,
  (req,res)=>{

    res.json({
      ok: true,
      user: publicUser(req.user)
    });
  }
);


/* =========================================================
   LOGOUT
   ========================================================= */

app.post(
  "/api/auth/logout",
  auth,
  (req,res)=>{

    res.json({
      ok: true,
      message: "Выход выполнен"
    });
  }
);


/* =========================================================
   PASSWORD CHANGE
   ========================================================= */

app.post(
  "/api/auth/password/change",
  auth,
  async (req,res)=>{

    try{

      const oldPassword =
        String(
          req.body.oldPassword || ""
        );

      const newPassword =
        String(
          req.body.newPassword || ""
        );

      if(newPassword.length < 6){

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

      if(!valid){

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

      saveDB();

      res.json({
        ok: true,
        message:
          "Пароль успешно изменён"
      });

    }catch(error){

      console.error(error);

      res.status(500).json({
        error:
          "Ошибка смены пароля"
      });
    }
  }
);


/* =========================================================
   PASSWORD RECOVERY
   =========================================================

   Для TESTNET.
   В production нужен отдельный recovery token/email.
   ========================================================= */

app.post(
  "/api/auth/recovery/reset",
  async (req,res)=>{

    try{

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

      if(!username || !newPassword){

        return res.status(400).json({
          error:
            "Недостаточно данных"
        });
      }

      if(newPassword.length < 6){

        return res.status(400).json({
          error:
            "Пароль должен содержать минимум 6 символов"
        });
      }

      const user =
        db.users.find(
          u =>
            u.username.toLowerCase() ===
            username.toLowerCase()
        );

      if(!user){

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

      saveDB();

      res.json({
        ok: true,
        message:
          "Пароль сброшен"
      });

    }catch(error){

      console.error(error);

      res.status(500).json({
        error:
          "Ошибка восстановления"
      });
    }
  }
);


/* =========================================================
   WALLET CREATION
   ========================================================= */

function createWalletForUser(
  userId,
  initial = false
){

  let address;

  do{

    address =
      walletAddress();

  }while(
    getWalletByAddress(address)
  );

  const wallet = {
    id: id("WLT_").toUpperCase(),
    userId,
    address,
    balance: initial ? 100 : 0,
    createdAt: now()
  };

  db.wallets.push(wallet);

  if(initial){

    db.network.totalSupply =
      round(
        db.network.totalSupply +
        wallet.balance
      );

    addTransaction({
      type: "genesis",
      to: wallet.address,
      amount: wallet.balance,
      fee: 0,
      walletId: wallet.id,
      userId
    });
  }

  return wallet;
}


/* =========================================================
   GET WALLETS
   ========================================================= */

app.get(
  "/api/wallets",
  auth,
  (req,res)=>{

    const list =
      getUserWallets(
        req.user.id
      ).map(publicWallet);

    res.json({
      ok: true,
      wallets: list,
      data: list
    });
  }
);


/* =========================================================
   CREATE WALLET
   ========================================================= */

app.post(
  "/api/wallet/create",
  auth,
  (req,res)=>{

    try{

      const wallet =
        createWalletForUser(
          req.user.id,
          false
        );

      if(!req.user.activeWalletId){

        req.user.activeWalletId =
          wallet.id;
      }

      saveDB();

      res.json({
        ok: true,
        wallet: publicWallet(wallet)
      });

    }catch(error){

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
  (req,res)=>{

    const walletId =
      req.body.walletId ||
      req.body.id;

    const wallet =
      getWallet(
        req.user.id,
        walletId
      );

    if(!wallet){

      return res.status(404).json({
        error:
          "Кошелёк не найден"
      });
    }

    req.user.activeWalletId =
      wallet.id;

    saveDB();

    res.json({
      ok: true,
      wallet: publicWallet(wallet)
    });
  }
);


/* =========================================================
   GET WALLET
   ========================================================= */

app.get(
  "/api/wallet/:id",
  auth,
  (req,res)=>{

    const wallet =
      getWallet(
        req.user.id,
        req.params.id
      );

    if(!wallet){

      return res.status(404).json({
        error:
          "Кошелёк не найден"
      });
    }

    res.json({
      ok: true,
      wallet: publicWallet(wallet)
    });
  }
);


/* =========================================================
   TRANSACTIONS
   ========================================================= */

function addTransaction(data){

  const tx = {

    id: id("tx_"),

    hash:
      crypto
        .createHash("sha256")
        .update(
          JSON.stringify({
            ...data,
            time: Date.now(),
            random:
              crypto.randomBytes(8).toString("hex")
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

    createdAt: now(),

    status: "confirmed"
  };

  db.transactions.push(tx);

  return tx;
}


/* =========================================================
   SEND
   ========================================================= */

app.post(
  "/api/send",
  auth,
  (req,res)=>{

    try{

      const to =
        String(
          req.body.to || ""
        ).trim().toUpperCase();

      const amount =
        round(
          number(req.body.amount)
        );

      if(!/^SLXC[A-F0-9]{32}$/.test(to)){

        return res.status(400).json({
          error:
            "Неверный адрес SLX"
        });
      }

      if(amount <= 0){

        return res.status(400).json({
          error:
            "Сумма должна быть больше 0"
        });
      }

      const wallet =
        getWallet(
          req.user.id,
          req.user.activeWalletId
        );

      if(!wallet){

        return res.status(400).json({
          error:
            "Активный кошелёк не найден"
        });
      }

      const recipient =
        getWalletByAddress(to);

      if(!recipient){

        return res.status(404).json({
          error:
            "Кошелёк получателя не найден в тестовой сети"
        });
      }

      if(
        recipient.userId ===
        wallet.userId
      ){

        return res.status(400).json({
          error:
            "Для теста используй другой кошелёк"
        });
      }

      const fee =
        TRANSFER_FEE;

      const total =
        round(
          amount + fee
        );

      if(wallet.balance < total){

        return res.status(400).json({
          error:
            `Недостаточно SLX. Нужно ${total} SLX`
        });
      }

      wallet.balance =
        round(
          wallet.balance - total
        );

      recipient.balance =
        round(
          recipient.balance + amount
        );

      const tx =
        addTransaction({
          type: "transfer",
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

    }catch(error){

      console.error(error);

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
  (req,res)=>{

    try{

      const walletId =
        req.body.walletId ||
        req.body.id ||
        req.user.activeWalletId;

      const wallet =
        getWallet(
          req.user.id,
          walletId
        );

      if(!wallet){

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

      const tx =
        addTransaction({
          type: "faucet",
          from: "SLX_FAUCET",
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
        transaction: tx
      });

    }catch(error){

      console.error(error);

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

app.get(
  "/api/transactions",
  auth,
  (req,res)=>{

    const wallets =
      getUserWallets(
        req.user.id
      );

    const addresses =
      new Set(
        wallets.map(
          wallet =>
            wallet.address.toUpperCase()
        )
      );

    const list =
      db.transactions
        .filter(tx =>
          addresses.has(
            String(tx.from || "")
              .toUpperCase()
          ) ||
          addresses.has(
            String(tx.to || "")
              .toUpperCase()
          )
        )
        .reverse();

    res.json({
      ok: true,
      transactions: list,
      data: list
    });
  }
);


/* Compatibility endpoint */

app.get(
  "/api/history",
  auth,
  (req,res)=>{

    const wallets =
      getUserWallets(
        req.user.id
      );

    const addresses =
      new Set(
        wallets.map(
          wallet =>
            wallet.address.toUpperCase()
        )
      );

    const list =
      db.transactions
        .filter(tx =>
          addresses.has(
            String(tx.from || "")
              .toUpperCase()
          ) ||
          addresses.has(
            String(tx.to || "")
              .toUpperCase()
          )
        )
        .reverse();

    res.json({
      ok: true,
      history: list,
      data: list
    });
  }
);


/* =========================================================
   BLOCKCHAIN
   ========================================================= */

function calculateBlockHash(block){

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

function createBlock(transaction){

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

    transactions:[
      transaction
    ],

    timestamp:
      Date.now(),

    hash:""
  };

  block.hash =
    calculateBlockHash(block);

  db.blocks.push(block);

  db.network.height =
    db.blocks.length;

  return block;
}


/* =========================================================
   BLOCKS
   ========================================================= */

app.get(
  "/api/blocks",
  (req,res)=>{

    const limit =
      Math.min(
        Number(req.query.limit) || 20,
        100
      );

    const blocks =
      db.blocks
        .slice(-limit)
        .reverse();

    res.json({
      ok: true,
      blocks,
      count: db.blocks.length,
      height: db.network.height,
      data: blocks
    });
  }
);


/* =========================================================
   NETWORK STATUS
   ========================================================= */

app.get(
  "/api/status",
  (req,res)=>{

    res.json({

      ok: true,

      status: "online",

      network:
        NETWORK,

      name:
        "SLX Network",

      version:
        VERSION,

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

      totalSupply:
        round(
          db.network.totalSupply
        ),

      uptime:
        process.uptime(),

      timestamp:
        now()
    });
  }
);


/* =========================================================
   ECONOMY
   ========================================================= */

app.get(
  "/api/economy",
  (req,res)=>{

    const circulating =
      db.wallets.reduce(
        (sum,wallet)=>
          sum + number(wallet.balance),
        0
      );

    const result = {

      network:
        NETWORK,

      version:
        VERSION,

      totalSupply:
        round(
          db.network.totalSupply
        ),

      circulatingSupply:
        round(circulating),

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
    };

    res.json({
      ok: true,
      ...result
    });
  }
);


/* =========================================================
   CHAIN VERIFY
   ========================================================= */

app.get(
  "/api/chain/verify",
  (req,res)=>{

    let valid = true;
    let error = null;

    for(
      let i = 0;
      i < db.blocks.length;
      i++
    ){

      const block =
        db.blocks[i];

      const expectedPrevious =
        i === 0
          ? "0".repeat(64)
          : db.blocks[i - 1].hash;

      if(
        block.previousHash !==
        expectedPrevious
      ){

        valid = false;

        error =
          `Ошибка previousHash в блоке ${i}`;

        break;
      }

      const calculated =
        calculateBlockHash(block);

      if(
        block.hash !==
        calculated
      ){

        valid = false;

        error =
          `Ошибка hash в блоке ${i}`;

        break;
      }
    }

    res.json({

      ok: valid,

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
   ADMIN / DEBUG
   ========================================================= */

app.get(
  "/api/debug",
  auth,
  (req,res)=>{

    res.json({
      version: VERSION,
      network: NETWORK,
      user: publicUser(req.user),
      wallets:
        getUserWallets(
          req.user.id
        ).map(publicWallet),
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
   STATIC FRONTEND
   ========================================================= */

const publicDir =
  path.join(
    __dirname,
    "public"
  );

if(fs.existsSync(publicDir)){

  app.use(
    express.static(publicDir)
  );

  app.get(
    "*",
    (req,res,next)=>{

      if(
        req.path.startsWith("/api/")
      ){
        return next();
      }

      const index =
        path.join(
          publicDir,
          "index.html"
        );

      if(fs.existsSync(index)){
        return res.sendFile(index);
      }

      next();
    }
  );
}


/* =========================================================
   ERROR HANDLER
   ========================================================= */

app.use(
  (err,req,res,next)=>{

    console.error(
      "SERVER ERROR:",
      err
    );

    res.status(500).json({
      error:
        "Внутренняя ошибка сервера"
    });
  }
);


/* =========================================================
   START
   ========================================================= */

app.listen(
  PORT,
  HOST,
  ()=>{
    console.log("");
    console.log(
      "===================================="
    );
    console.log(
      "        SLX NETWORK SERVER"
    );
    console.log(
      "===================================="
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
      "Port:",
      PORT
    );
    console.log(
      "Status: ONLINE"
    );
    console.log(
      "===================================="
    );
    console.log("");
  }
);