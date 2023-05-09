import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import * as dotenv from "dotenv";
import Joi from "joi";
import passwordComplexity from "joi-password-complexity";

dotenv.config();

const userSchema = new mongoose.Schema({
  nickname: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, select: false, required: true },
  images: [{ type: { id: String, url: String }, required: false }],
  refreshToken: [{ type: String, select: false, required: false }],
});

userSchema.methods.generateAuthToken = function (user) {
  const token = jwt.sign({ user: user.email }, process.env.JWTPRIVATEKEY, {
    expiresIn: "1h",
  });
  return token;
};

userSchema.methods.generateRefreshToken = function (user) {
  const refreshToken = jwt.sign(
    { user: user.email },
    process.env.JWTREFRESHKEY
  );
  return refreshToken;
};

// Middleware
export const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401); //.send({ message: "Not valid token" });
  jwt.verify(token, process.env.JWTPRIVATEKEY, (err, user) => {
    if (err) return res.sendStatus(403); //.send({ message: "Expired token" });
    req.user = user;
  });
  next();
};

export const validateRegister = (data) => {
  const schema = Joi.object({
    nickname: Joi.string().required(),
    email: Joi.string().email().required(),
    password: passwordComplexity().required(),
  });
  return schema.validate(data);
};

export const validateLogin = (data) => {
  const schema = Joi.object({
    email: Joi.string().email().required().label("Email"),
    password: Joi.string().required().label("Password"),
  });
  return schema.validate(data);
};

export const validateUpdate = (data) => {
  const schema = Joi.object({
    nickname: Joi.string().required(),
    email: Joi.string().email().required().label("Email"),
  });
  return schema.validate(data);
};

export const validatePassword = (data) => {
  const schema = Joi.object({
    password: Joi.string().required().label("Password"),
  });
  return schema.validate(data);
};

export const User = mongoose.model("user", userSchema);
