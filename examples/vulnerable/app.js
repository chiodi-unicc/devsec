const express = require("express");
const _ = require("lodash");
const { GITHUB_TOKEN } = require("./config");

const app = express();

app.get("/calc", (req, res) => {
  res.send(String(eval(req.query.x)));
});

app.listen(3000);
