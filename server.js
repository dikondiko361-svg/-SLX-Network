const express = require("express");
const path = require("path");
const fs = require("fs");

const app = express();

const PORT = process.env.PORT || 10000;
const HOST = "0.0.0.0";

const VERSION = "1.9.0";
const NETWORK = "SLX-Testnet";

const TRANSFER_FEE = 0.1;
const FAUCET_AMOUNT = 10;

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

/* =====================================================
   FIND FRONTEND
===================================================== */

const ROOT_INDEX = path.join(
  __dirname,
  "index.html"
);

const PUBLIC_DIR = path.join(
  __dirname,
  "public"
);

const PUBLIC_INDEX = path.join(
  PUBLIC_DIR,
  "index.html"
);

function getIndexFile() {

  if (fs.existsSync(ROOT_INDEX)) {
    return ROOT_INDEX;
  }

  if (fs.existsSync(PUBLIC_INDEX)) {
    return PUBLIC_INDEX;
  }

  return null;
}


/* =====================================================
   STATIC FILES
===================================================== */

if (fs.existsSync(PUBLIC_DIR)) {
  app.use(
    express.static(PUBLIC_DIR)
  );
}


/* =====================================================
   MAIN PAGE
===================================================== */

app.get("/", (req, res) => {

  const indexFile = getIndexFile();

  console.log(
    "INDEX:",
    indexFile || "NOT FOUND"
  );

  if (indexFile) {
    return res.sendFile(indexFile);
  }

  return res.status(500).send(`
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1">
<title>SLX Network</title>

<style>
body{
  margin:0;
  background:#080b12;
  color:#fff;
  font-family:Arial,sans-serif;
  padding:40px;
}

.box{
  max-width:600px;
  margin:auto;
  padding:25px;
  border:1px solid #263044;
  border-radius:20px;
  background:#101622;
}

h1{
  margin-top:0;
}

.good{
  color:#35d07f;
}

.bad{
  color:#ff6262;
}
</style>
</head>

<body>

<div class="box">

<h1>SLX Network</h1>

<p class="good">
Сервер работает.
</p>

<p class="bad">
index.html не найден.
</p>

<p>
Проверь, что файл находится здесь:
</p>

<pre>
index.html
</pre>

<p>
или здесь:
</p>

<pre>
public/index.html
</pre>

</div>

</body>
</html>
`);
});


/* =====================================================
   STATUS
===================================================== */

app.get(
  "/api/status",
  (req, res) => {

    res.json({

      name: "SLX Network",

      version: VERSION,

      network: NETWORK,

      status: "online",

      message:
        "SLX Network server is running",

      frontend:
        getIndexFile()
          ? "found"
          : "not_found",

      timestamp:
        new Date().toISOString()
    });
  }
);


/* =====================================================
   HEALTH
===================================================== */

app.get(
  "/api/health",
  (req, res) => {

    res.json({
      ok: true,
      status: "online",
      version: VERSION,
      network: NETWORK
    });
  }
);


/* =====================================================
   BASIC API COMPATIBILITY
===================================================== */

app.get(
  "/api/blocks",
  (req, res) => {

    res.json({
      ok: true,
      blocks: [],
      height: 0
    });
  }
);


app.get(
  "/api/economy",
  (req, res) => {

    res.json({

      ok: true,

      network: NETWORK,

      version: VERSION,

      totalSupply: 0,

      circulatingSupply: 0,

      transferFee:
        TRANSFER_FEE,

      faucetAmount:
        FAUCET_AMOUNT
    });
  }
);


app.get(
  "/api/chain/verify",
  (req, res) => {

    res.json({

      ok: true,

      valid: true,

      verified: true,

      blocks: 0
    });
  }
);


/* =====================================================
   API 404
===================================================== */

app.use(
  "/api",
  (req, res) => {

    res.status(404).json({

      ok: false,

      error:
        "API endpoint not found",

      path:
        req.path
    });
  }
);


/* =====================================================
   FRONTEND FALLBACK
===================================================== */

app.get(
  "*",
  (req, res) => {

    const indexFile =
      getIndexFile();

    if (indexFile) {
      return res.sendFile(
        indexFile
      );
    }

    res.status(404).send(
      "SLX Network frontend not found"
    );
  }
);


/* =====================================================
   START
===================================================== */

app.listen(
  PORT,
  HOST,
  () => {

    console.log("");
    console.log(
      "================================"
    );

    console.log(
      "       SLX NETWORK"
    );

    console.log(
      "================================"
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
      "Index:",
      getIndexFile() || "NOT FOUND"
    );

    console.log(
      "================================"
    );

    console.log("");
  }
);