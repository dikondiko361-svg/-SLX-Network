const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;

const wallets = new Map();

function makeId() {
  return "SLX" + crypto.randomBytes(5).toString("hex").toUpperCase();
}

function makeAddress() {
  return "SLX-" + crypto.randomBytes(8).toString("hex").toUpperCase();
}

function createWallet() {
  let id;

  do {
    id = makeId();
  } while (wallets.has(id));

  const wallet = {
    id,
    address: makeAddress(),
    balance: 1000,
    transactions: [],
    createdAt: new Date().toISOString()
  };

  wallets.set(id, wallet);

  return wallet;
}

function getWallet(id) {
  return wallets.get(String(id || "").trim().toUpperCase());
}

function addTransaction(wallet, transaction) {
  wallet.transactions.unshift(transaction);

  if (wallet.transactions.length > 50) {
    wallet.transactions =
      wallet.transactions.slice(0, 50);
  }
}

function sendJSON(res, data, status = 200) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*"
  });

  res.end(JSON.stringify(data));
}

function getBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", chunk => {
      body += chunk;
    });

    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error("Invalid JSON"));
      }
    });

    req.on("error", reject);
  });
}

function sendHTML(res) {
  fs.readFile(
    path.join(__dirname, "index.html"),
    "utf8",
    (error, html) => {

      if (error) {
        res.writeHead(500, {
          "Content-Type":
            "text/plain; charset=utf-8"
        });

        res.end("index.html not found");
        return;
      }

      res.writeHead(200, {
        "Content-Type":
          "text/html; charset=utf-8"
      });

      res.end(html);
    }
  );
}

const server = http.createServer(async (req, res) => {

  // MAIN PAGE
  if (
    req.method === "GET" &&
    req.url === "/"
  ) {
    sendHTML(res);
    return;
  }


  // NETWORK STATUS
  if (
    req.method === "GET" &&
    req.url === "/api/status"
  ) {

    sendJSON(res, {
      success: true,
      network: "SLX Testnet",
      version: "1.0",
      status: "online",
      wallets: Array.from(
        wallets.values()
      ).map(wallet => ({
        id: wallet.id,
        address: wallet.address,
        balance: wallet.balance
      }))
    });

    return;
  }


  // CREATE WALLET
  if (
    req.method === "POST" &&
    req.url === "/api/wallet/create"
  ) {

    const wallet = createWallet();

    sendJSON(res, {
      success: true,

      wallet: {
        id: wallet.id,
        address: wallet.address,
        balance: wallet.balance,
        transactions:
          wallet.transactions
      }
    });

    return;
  }


  // GET WALLET
  if (
    req.method === "GET" &&
    req.url.startsWith("/api/wallet/")
  ) {

    const id = decodeURIComponent(
      req.url.replace(
        "/api/wallet/",
        ""
      )
    );

    const wallet = getWallet(id);

    if (!wallet) {

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

    sendJSON(res, {
      success: true,

      wallet: {
        id: wallet.id,
        address: wallet.address,
        balance: wallet.balance,
        transactions:
          wallet.transactions
      }
    });

    return;
  }


  // FIND WALLET
  if (
    req.method === "GET" &&
    req.url.startsWith("/api/find/")
  ) {

    const id = decodeURIComponent(
      req.url.replace(
        "/api/find/",
        ""
      )
    );

    const wallet = getWallet(id);

    if (!wallet) {

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

    sendJSON(res, {
      success: true,

      recipient: {
        id: wallet.id,
        address: wallet.address
      }
    });

    return;
  }


  // FAUCET
  if (
    req.method === "POST" &&
    req.url === "/api/faucet"
  ) {

    try {

      const body =
        await getBody(req);

      const wallet =
        getWallet(body.id);

      if (!wallet) {

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

      const amount = 100;

      wallet.balance += amount;

      const transaction = {
        id:
          "TX-" +
          Date.now(),

        type: "faucet",

        amount,

        from: "FAUCET",

        to: wallet.id,

        time:
          new Date().toISOString()
      };

      addTransaction(
        wallet,
        transaction
      );

      sendJSON(res, {
        success: true,
        transaction,
        balance:
          wallet.balance
      });

    } catch {

      sendJSON(
        res,
        {
          success: false,
          error:
            "Ошибка запроса"
        },
        400
      );
    }

    return;
  }


  // SEND SLX
  if (
    req.method === "POST" &&
    req.url === "/api/send"
  ) {

    try {

      const body =
        await getBody(req);

      const sender =
        getWallet(body.sender);

      const recipient =
        getWallet(body.recipient);

      const amount =
        Number(body.amount);


      if (!sender) {

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


      if (!recipient) {

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
        !Number.isFinite(amount) ||
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


      sender.balance -= amount;

      recipient.balance += amount;


      const transactionId =
        "TX-" +
        Date.now() +
        "-" +
        crypto
          .randomBytes(3)
          .toString("hex");


      const time =
        new Date().toISOString();


      addTransaction(
        sender,
        {
          id: transactionId,
          type: "send",
          amount,
          from: sender.id,
          to: recipient.id,
          time
        }
      );


      addTransaction(
        recipient,
        {
          id: transactionId,
          type: "receive",
          amount,
          from: sender.id,
          to: recipient.id,
          time
        }
      );


      sendJSON(res, {
        success: true,

        transaction: {
          id: transactionId,
          amount,
          from: sender.id,
          to: recipient.id,
          time
        },

        senderBalance:
          sender.balance,

        recipientBalance:
          recipient.balance
      });

    } catch {

      sendJSON(
        res,
        {
          success: false,
          error:
            "Ошибка перевода"
        },
        400
      );
    }

    return;
  }


  // NOT FOUND
  sendJSON(
    res,
    {
      success: false,
      error: "Not found"
    },
    404
  );
});


server.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      "=============================="
    );

    console.log(
      "SLX Network v1.0"
    );

    console.log(
      "QR + SLX-ID Testnet"
    );

    console.log(
      "Server is LIVE"
    );

    console.log(
      "=============================="
    );
  }
);