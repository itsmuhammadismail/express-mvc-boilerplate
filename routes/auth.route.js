const express = require("express");
const {
  register,
  login,
  logout,
  newToken,
} = require("../controllers/auth.controller.js");
const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.get("/logout", logout);
router.get("/token", newToken);

module.exports = router;
