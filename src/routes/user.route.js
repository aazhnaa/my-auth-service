import express from "express";
import {signup,verifyEmail,login, refreshAccessToken, logout, logoutAllDevices, listSessions, revokeSession, resetPassword, forgetPassword} from '../controller/user.controller.js';
import { userMiddleware, rateLimiter } from "../middleware/user.middleware.js";
const router = express.Router();

router.post("/signup",rateLimiter({windowInSeconds: 60, maxRequests: 3, keyPrefix: "signup",}) ,signup);
router.post("/login",rateLimiter({windowInSeconds: 60, maxRequests: 20, keyPrefix: "login",}), login);
router.get("/verify-email",verifyEmail);
router.post("/refresh",rateLimiter({windowInSeconds: 60, maxRequests: 10, keyPrefix: "refresh",}), refreshAccessToken);
router.post("/logout", logout);
router.post("/logout-all",userMiddleware ,logoutAllDevices)
router.get("/sessions", userMiddleware, listSessions)
router.delete("/sessions/:sessionId", userMiddleware, revokeSession)
router.post("/forgot-password", forgetPassword);
router.post("/reset-password", resetPassword);

router.get("/protected", userMiddleware, (req,res)=>{
    res.json({
        message : "You are authorized",
        user : req.user
    });
})

export default router;