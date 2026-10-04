const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;

/* =========================
   FILE STORAGE
========================= */

const DATA_FILE =
  path.join(__dirname, "slx-data.json");

let database = {
  users: {},
  wallets: {}
};


/* =========================
   LOAD DATABASE
========================= */

function loadDatabase() {

  try {

    if (
      !fs.existsSync(
        DATA_FILE
      )
    ) {

      saveDatabase();

      console.log(
        "SLX database created."
      );

      return;

    }


    const raw =
      fs.readFileSync(
        DATA_FILE,
        "utf8"
      );


    const parsed =
      JSON.parse(raw);


    if (
      parsed &&
      typeof parsed === "object"
    ) {

      database.users =
        parsed.users || {};

      database.wallets =
        parsed.wallets || {};

    }


    console.log(
      "SLX database loaded."
    );

    console.log(
      "Users:",
      Object.keys(
        database.users
      ).length
    );

    console.log(
      "Wallets:",
      Object.keys(
        database.wallets
      ).length
    );

  }

  catch (error) {

    console.error(
      "Database load error:",
      error
    );

  }

}


/* =========================
   SAVE DATABASE
========================= */

function saveDatabase() {

  try {

    const temporaryFile =
      DATA_FILE + ".tmp";


    fs.writeFileSync(
      temporaryFile,
      JSON.stringify(
        database,
        null,
        2
      ),
      "utf8"
    );


    fs.renameSync(
      temporaryFile,
      DATA_FILE
    );


  }

  catch (error) {

    console.error(
      "Database save error:",
      error
    );

  }

}


/* =========================
   MEMORY SESSIONS
========================= */

const sessions =
  new Map();


/* =========================
   IDS
========================= */

function makeId() {

  let id;

  do {

    id =
      "SLX" +
      crypto
        .randomBytes(5)
        .toString("hex")
        .toUpperCase();

  }

  while (
    database.wallets[id]
  );


  return id;

}


function makeAddress() {

  return (
    "SLX-" +
    crypto
      .randomBytes(8)
      .toString("hex")
      .toUpperCase()
  );

}


function makeUserId() {

  return (
    "USR-" +
    crypto
      .randomBytes(8)
      .toString("hex")
      .toUpperCase()
  );

}


function makeSessionToken() {

  return crypto
    .randomBytes(32)
    .toString("hex");

}


/* =========================
   PASSWORD HASH
========================= */

function hashPassword(
  password
) {

  return crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");

}


/* =========================
   WALLET
========================= */

function createWallet() {

  const id =
    makeId();


  const wallet = {

    id,

    address:
      makeAddress(),

    balance:
      1000,

    transactions: [],

    createdAt:
      new Date().toISOString()

  };


  database.wallets[id] =
    wallet;


  saveDatabase();


  return wallet;

}


function getWallet(id) {

  const key =
    String(
      id || ""
    )
      .trim()
      .toUpperCase();


  return database.wallets[key];

}


/* =========================
   TRANSACTIONS
========================= */

function addTransaction(
  wallet,
  transaction
) {

  wallet.transactions.unshift(
    transaction
  );


  if (
    wallet.transactions.length >
    50
  ) {

    wallet.transactions =
      wallet.transactions.slice(
        0,
        50
      );

  }

}


/* =========================
   USER
========================= */

function findUserByUsername(
  username
) {

  const target =
    String(
      username || ""
    )
      .trim()
      .toLowerCase();


  for (
    const userId
    of Object.keys(
      database.users
    )
  ) {

    const user =
      database.users[userId];


    if (
      user.username
        .toLowerCase() ===
      target
    ) {

      return user;

    }

  }


  return null;

}


/* =========================
   SESSION
========================= */

function getToken(req) {

  const header =
    req.headers.authorization ||
    "";


  if (
    !header.startsWith(
      "Bearer "
    )
  ) {

    return null;

  }


  return header
    .substring(7)
    .trim();

}


function getUserByToken(
  req
) {

  const token =
    getToken(req);


  if (!token) {

    return null;

  }


  const userId =
    sessions.get(
      token
    );


  if (!userId) {

    return null;

  }


  return database.users[
    userId
  ] || null;

}


/* =========================
   JSON RESPONSE
========================= */

function sendJSON(
  res,
  data,
  status = 200
) {

  res.writeHead(
    status,
    {
      "Content-Type":
        "application/json; charset=utf-8",

      "Access-Control-Allow-Origin":
        "*",

      "Access-Control-Allow-Headers":
        "Content-Type, Authorization"
    }
  );


  res.end(
    JSON.stringify(
      data
    )
  );

}


/* =========================
   REQUEST BODY
========================= */

function getBody(req) {

  return new Promise(
    (
      resolve,
      reject
    ) => {

      let body = "";


      req.on(
        "data",
        chunk => {

          body +=
            chunk;

        }
      );


      req.on(
        "end",
        () => {

          try {

            resolve(
              body
                ? JSON.parse(body)
                : {}
            );

          }

          catch {

            reject(
              new Error(
                "Invalid JSON"
              )
            );

          }

        }
      );


      req.on(
        "error",
        reject
      );

    }
  );

}


/* =========================
   HTML
========================= */

function sendHTML(
  res
) {

  fs.readFile(
    path.join(
      __dirname,
      "index.html"
    ),
    "utf8",
    (
      error,
      html
    ) => {

      if (error) {

        res.writeHead(
          500,
          {
            "Content-Type":
              "text/plain; charset=utf-8"
          }
        );


        res.end(
          "index.html not found"
        );


        return;

      }


      res.writeHead(
        200,
        {
          "Content-Type":
            "text/html; charset=utf-8"
        }
      );


      res.end(
        html
      );

    }
  );

}


/* =========================
   SERVER
========================= */

const server =
  http.createServer(
    async (
      req,
      res
    ) => {

      try {

        /* =========================
           MAIN PAGE
        ========================= */

        if (
          req.method === "GET" &&
          req.url === "/"
        ) {

          sendHTML(
            res
          );

          return;

        }


        /* =========================
           REGISTER
        ========================= */

        if (
          req.method === "POST" &&
          req.url ===
            "/api/auth/register"
        ) {

          const body =
            await getBody(
              req
            );


          const username =
            String(
              body.username || ""
            ).trim();


          const password =
            String(
              body.password || ""
            );


          if (
            username.length < 3 ||
            username.length > 20
          ) {

            sendJSON(
              res,
              {
                success: false,
                error:
                  "Имя должно содержать от 3 до 20 символов."
              },
              400
            );


            return;

          }


          if (
            !/^[a-zA-Z0-9_]+$/
              .test(username)
          ) {

            sendJSON(
              res,
              {
                success: false,
                error:
                  "Имя может содержать только буквы, цифры и _."
              },
              400
            );


            return;

          }


          if (
            password.length < 6
          ) {

            sendJSON(
              res,
              {
                success: false,
                error:
                  "Пароль должен содержать минимум 6 символов."
              },
              400
            );


            return;

          }


          const existingUser =
            findUserByUsername(
              username
            );


          if (
            existingUser
          ) {

            sendJSON(
              res,
              {
                success: false,
                error:
                  "Это имя уже зарегистрировано."
              },
              409
            );


            return;

          }


          const wallet =
            createWallet();


          const userId =
            makeUserId();


          const user = {

            id:
              userId,

            username:
              username,

            passwordHash:
              hashPassword(
                password
              ),

            walletId:
              wallet.id,

            createdAt:
              new Date()
                .toISOString()

          };


          database.users[
            userId
          ] =
            user;


          saveDatabase();


          const token =
            makeSessionToken();


          sessions.set(
            token,
            userId
          );


          sendJSON(
            res,
            {

              success:
                true,

              token:

                token,

              user: {

                id:
                  user.id,

                username:
                  user.username,

                walletId:
                  user.walletId

              },

              wallet: {

                id:
                  wallet.id,

                address:
                  wallet.address,

                balance:
                  wallet.balance

              }

            }
          );


          return;

        }


        /* =========================
           LOGIN
        ========================= */

        if (
          req.method === "POST" &&
          req.url ===
            "/api/auth/login"
        ) {

          const body =
            await getBody(
              req
            );


          const username =
            String(
              body.username || ""
            ).trim();


          const password =
            String(
              body.password || ""
            );


          const user =
            findUserByUsername(
              username
            );


          if (
            !user
          ) {

            sendJSON(
              res,
              {
                success: false,
                error:
                  "Неверное имя или пароль."
              },
              401
            );


            return;

          }


          const passwordHash =
            hashPassword(
              password
            );


          if (
            user.passwordHash !==
            passwordHash
          ) {

            sendJSON(
              res,
              {
                success: false,
                error:
                  "Неверное имя или пароль."
              },
              401
            );


            return;

          }


          const token =
            makeSessionToken();


          sessions.set(
            token,
            user.id
          );


          const wallet =
            getWallet(
              user.walletId
            );


          sendJSON(
            res,
            {

              success:
                true,

              token:
                token,

              user: {

                id:
                  user.id,

                username:
                  user.username,

                walletId:
                  user.walletId

              },

              wallet:
                wallet
                  ? {

                      id:
                        wallet.id,

                      address:
                        wallet.address,

                      balance:
                        wallet.balance

                    }
                  : null

            }
          );


          return;

        }


        /* =========================
           CURRENT USER
        ========================= */

        if (
          req.method === "GET" &&
          req.url ===
            "/api/auth/me"
        ) {

          const user =
            getUserByToken(
              req
            );


          if (
            !user
          ) {

            sendJSON(
              res,
              {
                success: false,
                error:
                  "Не авторизован."
              },
              401
            );


            return;

          }


          const wallet =
            getWallet(
              user.walletId
            );


          sendJSON(
            res,
            {

              success:
                true,

              user: {

                id:
                  user.id,

                username:
                  user.username,

                walletId:
                  user.walletId

              },

              wallet:
                wallet
                  ? {

                      id:
                        wallet.id,

                      address:
                        wallet.address,

                      balance:
                        wallet.balance

                    }
                  : null

            }
          );


          return;

        }


        /* =========================
           LOGOUT
        ========================= */

        if (
          req.method === "POST" &&
          req.url ===
            "/api/auth/logout"
        ) {

          const token =
            getToken(
              req
            );


          if (
            token
          ) {

            sessions.delete(
              token
            );

          }


          sendJSON(
            res,
            {
              success:
                true
            }
          );


          return;

        }


        /* =========================
           NETWORK STATUS
        ========================= */

        if (
          req.method === "GET" &&
          req.url ===
            "/api/status"
        ) {

          const wallets =
            Object.values(
              database.wallets
            );


          sendJSON(
            res,
            {

              success:
                true,

              network:
                "SLX Testnet",

              version:
                "1.2",

              status:
                "online",

              accounts:
                Object.keys(
                  database.users
                ).length,

              wallets:
                wallets.map(
                  wallet => ({

                    id:
                      wallet.id,

                    address:
                      wallet.address,

                    balance:
                      wallet.balance

                  })
                )

            }
          );


          return;

        }


        /* =========================
           CREATE WALLET
        ========================= */

        if (
          req.method === "POST" &&
          req.url ===
            "/api/wallet/create"
        ) {

          const wallet =
            createWallet();


          sendJSON(
            res,
            {

              success:
                true,

              wallet: {

                id:
                  wallet.id,

                address:
                  wallet.address,

                balance:
                  wallet.balance,

                transactions:
                  wallet.transactions

              }

            }
          );


          return;

        }


        /* =========================
           GET WALLET
        ========================= */

        if (
          req.method === "GET" &&
          req.url.startsWith(
            "/api/wallet/"
          )
        ) {

          const id =
            decodeURIComponent(
              req.url.replace(
                "/api/wallet/",
                ""
              )
            );


          const wallet =
            getWallet(
              id
            );


          if (
            !wallet
          ) {

            sendJSON(
              res,
              {
                success: false,
                error:
                  "SLX-ID не найден"
              },
              404
            );


            return;

          }


          sendJSON(
            res,
            {

              success:
                true,

              wallet: {

                id:
                  wallet.id,

                address:
                  wallet.address,

                balance:
                  wallet.balance,

                transactions:
                  wallet.transactions

              }

            }
          );


          return;

        }


        /* =========================
           FIND WALLET
        ========================= */

        if (
          req.method === "GET" &&
          req.url.startsWith(
            "/api/find/"
          )
        ) {

          const id =
            decodeURIComponent(
              req.url.replace(
                "/api/find/",
                ""
              )
            );


          const wallet =
            getWallet(
              id
            );


          if (
            !wallet
          ) {

            sendJSON(
              res,
              {
                success: false,
                error:
                  "Получатель не найден"
              },
              404
            );


            return;

          }


          sendJSON(
            res,
            {

              success:
                true,

              recipient: {

                id:
                  wallet.id,

                address:
                  wallet.address

              }

            }
          );


          return;

        }


        /* =========================
           FAUCET
        ========================= */

        if (
          req.method === "POST" &&
          req.url ===
            "/api/faucet"
        ) {

          const body =
            await getBody(
              req
            );


          const wallet =
            getWallet(
              body.id
            );


          if (
            !wallet
          ) {

            sendJSON(
              res,
              {
                success: false,
                error:
                  "Кошелёк не найден"
              },
              404
            );


            return;

          }


          const amount =
            100;


          wallet.balance +=
            amount;


          const transaction = {

            id:
              "TX-" +
              Date.now(),

            type:
              "faucet",

            amount:
              amount,

            from:
              "FAUCET",

            to:
              wallet.id,

            time:
              new Date()
                .toISOString()

          };


          addTransaction(
            wallet,
            transaction
          );


          saveDatabase();


          sendJSON(
            res,
            {

              success:
                true,

              transaction:
                transaction,

              balance:
                wallet.balance

            }
          );


          return;

        }


        /* =========================
           SEND SLX
        ========================= */

        if (
          req.method === "POST" &&
          req.url ===
            "/api/send"
        ) {

          const body =
            await getBody(
              req
            );


          const sender =
            getWallet(
              body.sender
            );


          const recipient =
            getWallet(
              body.recipient
            );


          const amount =
            Number(
              body.amount
            );


          if (
            !sender
          ) {

            sendJSON(
              res,
              {
                success: false,
                error:
                  "Ваш кошелёк не найден"
              },
              404
            );


            return;

          }


          if (
            !recipient
          ) {

            sendJSON(
              res,
              {
                success: false,
                error:
                  "Получатель не найден"
              },
              404
            );


            return;

          }


          if (
            sender.id ===
            recipient.id
          ) {

            sendJSON(
              res,
              {
                success: false,
                error:
                  "Нельзя отправить самому себе"
              },
              400
            );


            return;

          }


          if (
            !Number.isFinite(
              amount
            ) ||
            amount <= 0
          ) {

            sendJSON(
              res,
              {
                success: false,
                error:
                  "Неверная сумма"
              },
              400
            );


            return;

          }


          if (
            amount >
            sender.balance
          ) {

            sendJSON(
              res,
              {
                success: false,
                error:
                  "Недостаточно SLX"
              },
              400
            );


            return;

          }


          sender.balance -=
            amount;


          recipient.balance +=
            amount;


          const transactionId =
            "TX-" +
            Date.now() +
            "-" +
            crypto
              .randomBytes(3)
              .toString("hex");


          const time =
            new Date()
              .toISOString();


          addTransaction(
            sender,
            {

              id:
                transactionId,

              type:
                "send",

              amount:
                amount,

              from:
                sender.id,

              to:
                recipient.id,

              time:
                time

            }
          );


          addTransaction(
            recipient,
            {

              id:
                transactionId,

              type:
                "receive",

              amount:
                amount,

              from:
                sender.id,

              to:
                recipient.id,

              time:
                time

            }
          );


          saveDatabase();


          sendJSON(
            res,
            {

              success:
                true,

              transaction: {

                id:
                  transactionId,

                amount:
                  amount,

                from:
                  sender.id,

                to:
                  recipient.id,

                time:
                  time

              },

              senderBalance:
                sender.balance,

              recipientBalance:
                recipient.balance

            }
          );


          return;

        }


        /* =========================
           NOT FOUND
        ========================= */

        sendJSON(
          res,
          {
            success:
              false,

            error:
              "Not found"
          },
          404
        );

      }

      catch (error) {

        console.error(
          "SERVER ERROR:",
          error
        );


        sendJSON(
          res,
          {
            success:
              false,

            error:
              "Внутренняя ошибка сервера."
          },
          500
        );

      }

    }
  );


/* =========================
   START
========================= */

loadDatabase();


server.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      "=============================="
    );

    console.log(
      "SLX Network v1.2"
    );

    console.log(
      "Persistent Account + Wallet"
    );

    console.log(
      "Server is LIVE"
    );

    console.log(
      "=============================="
    );

  }
);