import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
dotenv.config();
import userRoutes from "./src/routes/user.route.js";

const app = express();

app.use(helmet());
app.use(express.json());
app.use(cors());
app.use(morgan("dev"));
app.use("/auth", userRoutes);

app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok" });
});

export default app;