const jwt = require("jsonwebtoken");
const asyncHandler = require("express-async-handler");
const bcrypt = require("bcryptjs");
const User = require("../models/user.model.js");
const {
  generateAccessToken,
  generateRefreshToken,
} = require("../functions/generate_tokens.js");

// @desc    Authenticate a user
// @route   POST /api/login
// @access  Public
const login = asyncHandler(async (req, res) => {
  const { username, password } = req.body;

  if ((!username, !password)) {
    res.status(400);
    throw new Error("Username and password are required.");
  }

  // Check for register user name
  const user = await User.findOne({ username });

  if (await bcrypt.compare(password, user.password)) {
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // Saving refreshToken with current user
    user.refreshToken = refreshToken;
    const result = await user.save();

    res.cookie("jwt", refreshToken, {
      httpOnly: true,
      sameSite: "None",
      secure: true,
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.json({
      _id: user.id,
      username: user.username,
      email: user.email,
      token: accessToken,
      status: "success",
    });
  } else {
    res.status(400);
    throw new Error("Invalid username or password.");
  }
});

// @desc    Register new user
// @route   POST /api/register
// @access  Public
const register = asyncHandler(async (req, res) => {
  const { username, email, password } = req.body;
  if ((!username, !email, !password)) {
    res.status(400);
    throw new Error("Please add all fields");
  }

  // Check if user exists
  const userExists = await User.findOne({ username });

  if (userExists) {
    res.status(400);
    throw new Error("User already exists");
  }

  // Hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  // Create user
  const user = await User.create({
    username,
    email,
    password: hashedPassword,
  });

  if (user) {
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // Saving refreshToken with current user
    user.refreshToken = refreshToken;
    const result = await user.save();

    res.cookie("jwt", refreshToken, {
      httpOnly: true,
      sameSite: "None",
      // secure: true,
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.status(201).json({
      _id: user.id,
      username: user.username,
      token: accessToken,
      status: "success",
    });
  } else {
    res.status(400);
    throw new Error("Invalid user data");
  }
});

// @desc    Authenticate a user
// @route   POST /api/logout
// @access  Public
const logout = asyncHandler(async (req, res) => {
  // On client, also delete the accessToken

  const cookies = req.cookies;
  if (!cookies?.jwt) return res.status(204); //No content
  const refreshToken = cookies.jwt;

  // Is refreshToken in db?
  const foundUser = await User.findOne({ refreshToken });
  if (!foundUser) {
    res.clearCookie("jwt", { httpOnly: true, sameSite: "None", secure: true });
    return res.status(204);
  }

  // Delete refreshToken in db
  foundUser.refreshToken = "";
  const result = await foundUser.save();

  res.clearCookie("jwt", { httpOnly: true, sameSite: "None", secure: true });
  res.status(204);
});

// @desc    Authenticate a user
// @route   POST /api/token
// @access  Public
const newToken = asyncHandler(async (req, res) => {
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.sendStatus(401);
  const refreshToken = cookies.jwt;

  const foundUser = await User.findOne({ refreshToken }).exec();
  if (!foundUser) return res.status(403); //Forbidden
  // evaluate jwt
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
    if (err || foundUser._id !== decoded._id) return res.status(403);
    const accessToken = generateAccessToken(foundUser._id);
    res.status(201).json({ accessToken });
  });
});

module.exports = {
  login,
  register,
  logout,
  newToken,
};
