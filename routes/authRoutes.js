import express from "express";
import axios from "axios";
import { Storage } from "@google-cloud/storage";
import path from "path";
import { fileURLToPath } from "url";
import stream from "stream";
import * as dotenv from "dotenv";
import bcrypt from "bcrypt";
import {
  User,
  validateLogin,
  authenticateToken,
  validateRegister,
  validateUpdate,
  validatePassword,
} from "../mongodb/models/user.js";

dotenv.config();

const router = express.Router();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const storage = new Storage({
  projectId: "neurosketch",
  keyFilename: path.join(__dirname, "..", "gcs", "keys.json"),
});

const bucket = storage.bucket("neurosketch");

router.post("/token", async (req, res) => {
  try {
    if (req.body.refreshToken == null)
      return res.status(401).send({ message: "Not valid token" });
    const user = await User.findOne({ refreshToken: req.body.refreshToken }).select(
      "+refreshToken"
    );
    if (!user) return res.status(401).send({ message: "Not user found" });
    const authtoken = user.generateAuthToken(user);
    const refreshToken = user.generateRefreshToken(user);
    const index = user.refreshToken.indexOf(req.body.refreshToken);
    user.refreshToken[index] = refreshToken;
    user.save();
    return res
      .status(200)
      .send({ authToken: authtoken, refreshToken: refreshToken });
  } catch (error) {
    res.status(500).send({ message: "Internal server error" });
  }
});

router.post("/register", async (req, res) => {
  try {
    const { error } = validateRegister(req.body);
    if (error)
      return res.status(400).send({ message: error.details[0].message });
    const user = await User.findOne({ email: req.body.email });
    if (user)
      return res
        .status(409)
        .send({ message: "User with given email already exists" });
    const salt = await bcrypt.genSalt(Number(process.env.SALT));
    const hashPassword = await bcrypt.hash(req.body.password, salt);
    const createdUser = await new User({
      ...req.body,
      password: hashPassword,
    }).save();
    return res.status(201).send({ message: "User created successfully" });
  } catch (error) {
    return res.status(500).send({ message: "Internal server error" });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { error } = validateLogin({
      email: req.body.email,
      password: req.body.password,
    });
    if (error)
      return res.status(400).send({ message: error.details[0].message });
    const user = await User.findOne({ email: req.body.email }).select(
      "+password"
    );
    if (!user)
      return res.status(401).send({ message: "Invalid email or password" });

    const validPassword = await bcrypt.compare(
      req.body.password,
      user.password
    );
    if (!validPassword)
      return res.status(401).send({ message: "Invalid email or password" });

    const authtoken = user.generateAuthToken(user);
    const refreshToken = user.generateRefreshToken(user);
    user.refreshToken.push(refreshToken);
    user.save();
    res.status(200).send({
      authToken: authtoken,
      refreshToken: refreshToken,
      message: "Logged in successfully",
    });
  } catch (error) {
    res.status(500).send({ message: "Internal server error" });
  }
});

router.delete("/logout", async (req, res) => {
  const user = await User.findOne({ refreshToken: req.body.refreshToken });
  user.refreshToken.pop(req.body.refreshToken);
  user.save();
  return res.status(204).send({ message: "Successfully logout" });
});

router.get("/content", authenticateToken, (req, res) => {
  res.send({ message: "content" });
});

router.get("/getUser", authenticateToken, async (req, res) => {
  const user = await User.findOne({ email: req.user.user });
  return res.send(user);
});

router.post("/updateUser", authenticateToken, async (req, res) => {
  const user = await User.findOne({ email: req.user.user });
  const { error } = validateUpdate({
    nickname: req.body.nickname,
    email: req.body.email,
  });
  if (error) return res.status(400).send({ message: error.details[0].message });
  user.nickname = req.body.nickname;
  user.email = req.body.email;
  user.save();
  return res.status(204).send({ message: "User updated successfully" });
});

router.post("/changePassword", authenticateToken, async (req, res) => {
  const user = await User.findOne({ email: req.user.user }).select("+password");
  const validPassword = await bcrypt.compare(
    req.body.currentPassword,
    user.password
  );
  if (!validPassword)
    return res.status(401).send({ message: "Invalid password" });
  const { error } = validatePassword({
    password: req.body.newPassword,
  });
  if (error) return res.status(400).send({ message: error.details[0].message });
  user.password = req.body.newPassword;
  user.save();
  return res.status(204).send({ message: "Password updated successfully" });
});

router.post("/uploadImage", authenticateToken, async (req, res) => {
  const response = await axios.get(req.body.url, {
    responseType: "arraybuffer",
  });
  const buffer = Buffer.from(response.data, "utf-8");

  const filename = `${Date.now()}-${req.user.user}.jpg`;
  const file = bucket.file(`${filename}`);
  file.on("error", function (err) {
    return res.status(401).send({ message: err });
  });

  const passthroughStream = new stream.PassThrough();
  passthroughStream.write(buffer);
  passthroughStream.end();

  async function streamFileUpload() {
    passthroughStream
      .pipe(file.createWriteStream())
      .on("finish", async () => {
        await bucket.file(`${filename}`).makePublic();
        const url = `https://storage.googleapis.com/neurosketch/${filename}`;
        const user = await User.findOne({ email: req.user.user });
        const imageToPush = {
          id: req.body.id,
          url: url,
        };
        user.images.push(imageToPush);
        user.save();

        return res.send({ url: url, message: "Image saved successfully" });
      })
      .on("error", function (err) {
        return res.status(401).send({ message: err });
      });
  }

  await streamFileUpload().catch(function (err) {
    return res.status(401).send({ message: err });
  });
});

export default router;
