const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
require("dotenv").config();

const app = express();

/* =======================
   MIDDLEWARE
======================= */
app.use(cors());
app.use(express.json());
app.use(helmet());

/* =======================
   ENV CHECK
======================= */
if (!process.env.MONGO_URI || !process.env.JWT_SECRET) {
  console.error("❌ Missing MONGO_URI or JWT_SECRET in .env");
  process.exit(1);
}

/* =======================
   DB CONNECT
======================= */
mongoose.set("strictQuery", true);

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => {
    console.error("❌ MongoDB error", err.message);
    process.exit(1);
  });

/* =======================
   ASYNC HANDLER (FIX)
======================= */
const asyncHandler = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

/* =======================
   MODELS
======================= */

// User
const userSchema = new mongoose.Schema(
  {
    name: String,
    email: { type: String, unique: true, lowercase: true },
    password: String,
    profilePic: { type: String, default: "" },
    isOnline: { type: Boolean, default: false }
  },
  { timestamps: true }
);

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

const User = mongoose.model("User", userSchema);

// Chat
const chatSchema = new mongoose.Schema(
  {
    users: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    lastMessage: String
  },
  { timestamps: true }
);

const Chat = mongoose.model("Chat", chatSchema);

// Message
const messageSchema = new mongoose.Schema(
  {
    chatId: { type: mongoose.Schema.Types.ObjectId, ref: "Chat" },
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    text: String,
    seen: { type: Boolean, default: false }
  },
  { timestamps: true }
);

const Message = mongoose.model("Message", messageSchema);

/* =======================
   AUTH (FIXED)
======================= */
const protect = asyncHandler(async (req, res, next) => {
  const auth = req.headers.authorization;

  if (!auth || !auth.startsWith("Bearer "))
    return res.status(401).json({ message: "No token provided" });

  const token = auth.split(" ")[1];
  const decoded = jwt.verify(token, process.env.JWT_SECRET);

  const user = await User.findById(decoded.id).select("-password");
  if (!user) return res.status(401).json({ message: "User not found" });

  req.user = user;
  next();
});

/* =======================
   ROUTES
======================= */

app.get("/", (req, res) => {
  res.send("Message server is live now");
});

app.get("/health", (req, res) => {
  res.json({ status: "OK", uptime: process.uptime() });
});

/* ---------- USERS ---------- */

app.post(
  "/api/users",
  asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password)
      return res.status(400).json({ message: "All fields required" });

    if (await User.findOne({ email }))
      return res.status(409).json({ message: "User already exists" });

    const user = await User.create({ name, email, password });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d"
    });

    res.status(201).json({
      user: { id: user._id, name: user.name, email: user.email },
      token
    });
  })
);

app.post(
  "/api/users/login",
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d"
    });

    res.json({
      user: { id: user._id, name: user.name, email: user.email },
      token
    });
  })
);

app.get("/api/users", protect, asyncHandler(async (req, res) => {
  res.json(await User.find().select("-password"));
}));

/* ---------- CHATS ---------- */

app.post("/api/chats", protect, asyncHandler(async (req, res) => {
  const { users } = req.body;

  if (!Array.isArray(users) || users.length < 2)
    return res.status(400).json({ message: "At least 2 users required" });

  if (!users.includes(req.user._id.toString()))
    users.push(req.user._id);

  const chat =
    (await Chat.findOne({ users: { $all: users, $size: users.length } })) ||
    (await Chat.create({ users }));

  res.json(await chat.populate("users", "-password"));
}));

app.get("/api/chats", protect, asyncHandler(async (req, res) => {
  res.json(
    await Chat.find({ users: req.user._id }).populate("users", "-password")
  );
}));

/* ---------- MESSAGES ---------- */

app.post("/api/messages", protect, asyncHandler(async (req, res) => {
  const { chatId, text } = req.body;

  const chat = await Chat.findById(chatId);
  if (!chat || !chat.users.includes(req.user._id))
    return res.status(403).json({ message: "Access denied" });

  const message = await Message.create({
    chatId,
    senderId: req.user._id,
    text
  });

  chat.lastMessage = text;
  await chat.save();

  res.status(201).json(
    await message.populate("senderId", "name profilePic")
  );
}));

app.get("/api/messages/:chatId", protect, asyncHandler(async (req, res) => {
  res.json(
    await Message.find({ chatId: req.params.chatId })
      .populate("senderId", "name profilePic")
      .sort({ createdAt: 1 })
  );
}));

/* =======================
   ERROR HANDLER (FIX)
======================= */
app.use((err, req, res, next) => {
  console.error("🔥", err.message);
  res.status(500).json({ message: err.message || "Server error" });
});

/* =======================
   SERVER
======================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on http://localhost:${PORT}`)
);
