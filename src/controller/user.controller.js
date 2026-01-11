import User from '../model/user.model.js';
import Session from '../model/session.model.js';
import validator from "validator"; //for email validation
import mongoose from "mongoose";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import { generateToken } from '../lib/token.js';
import { redis } from '../lib/redis.js';
import { checkLoginLock, recordLoginFailure, resetLoginFailures } from '../lib/utils.js';

export const signup = async(req, res) =>{
    const {email, password, username} = req.body;
    try{
        if(!email || !password || !username){
            return res.status(400).json({message:"all fields must be filled!"})
        } 
        if(!validator.isEmail(email)){
            return res.status(400).json({message:"invalid email format"});
        }
        const existingUser = await User.findOne({$or:[{email},{username}]});
        if(existingUser){
            return res.status(409).json({message:"User already exists."});
        }
        if(password.length < 6){
            return res.status(400).json({message : "Password must be of at least 6 characters"})
        }

        const hashedPassword = await bcrypt.hash(password,10);
        const newUser = await User.create({
            email,
            username,
            password:hashedPassword,
            role:"user",
            isEmailVerified:false,
        })
        
        const emailToken = crypto.randomBytes(32).toString("hex");
        const key = `verify:${newUser._id.toString()}`;
        await redis.set(key, emailToken, {
            ex: 900
        });


        return res.status(201).json({
            message: "Signup successful. Check your email to verify your account.",
            user: {
                _id: newUser._id,
                username: newUser.username,
                email: newUser.email,
            },
            devEmailToken: emailToken, // remove in production
        });
    }
    catch (error) {
        console.log("Error in signup controller : ", error.message)
        res.status(400).json({message:"internal server error"})
    }
}

export const verifyEmail = async(req, res) =>{
    const {userId, token} = req.query;
    try{
        if(!userId || !token){_
            return res.status(400).json({message:"Invalid verification link."});
        }
        const storedToken = await redis.get(`verify:${userId}`);
        if(!storedToken || storedToken !== token){
            return res.status(400).json({message:"Invalid or expired verification link."});
        }

        await User.findByIdAndUpdate(userId, {isEmailVerified:true});
        await redis.del(`verify:${userId}`);
        return res.json({message:"Email verified successfully."});
    }catch(error){
        console.log("Error in email verification controller : ", error.message)
        return res.status(500).json({message:"Internal server error"});
    }
}

//with progressive lockout
export const login = async(req, res) =>{
    let {email, password} = req.body;
    try {
        if(!email || !password){
            return res.status(400).json({message:"All fields must be filled!"});
        }

        email = email.toLowerCase();

        const lockTTL = await checkLoginLock(email);
        if(lockTTL){
            return res.status(423).json({message: `Account temporarily locked. Try again in ${lockTTL} seconds.`});
        }

        const existingUser = await User.findOne({email});
        if(!existingUser){
            await recordLoginFailure(email);
            return res.status(401).json({message:"Invalid email or password."});
        }
        if(!existingUser.isEmailVerified){
            return res.status(403).json({message:"Email not verified. Please check your email."});
        }

        const isMatch = await bcrypt.compare(password, existingUser.password);
        if(!isMatch){
            await recordLoginFailure(email);
            return res.status(401).json({message:"Invalid email or password."});
        }


        //access token generation - for API requests
        const accessToken = generateToken(existingUser._id, existingUser.role, "15m");

        //refresh token generation - for session management
        const refreshToken = crypto.randomBytes(40).toString("hex");

        //detect device info 
        const userAgent = req.headers['user-agent'];
        const deviceInfo = userAgent || "Unknown device";

        //create session in db
        await Session.create({
            userId : existingUser._id,
            refreshToken,
            deviceInfo,
            ip:req.ip,
            expiry: new Date(Date.now() + 7*24*60*60*1000) //7 days
        })

        await resetLoginFailures(email);
        //return to client
        return res.status(200).json({
            message:"Login successful",
            accessToken,
            refreshToken,
            user:{
                _id:existingUser._id,
                username:existingUser.username,
                email:existingUser.email,
                role:existingUser.role
            }
        })
    } catch (error) {
        console.log("Error in login controller : ", error.message);
        return res.status(500).json({message:"Internal server error"});
    }
}

export const refreshAccessToken = async(req, res) =>{
    // token rotation
    const { refreshToken } = req.body;
    try {
        if(!refreshToken){
            return res.status(401).json({message:"Refresh token required"});
        }

        const session = await Session.findOne({refreshToken});
        if(!session){
            return res.status(403).json({message:"Invalid or expired refresh token"});
        }

        const user = await User.findById(session.userId);
        if(!user){
            await Session.deleteOne({_id:session._id});
            return res.status(403).json({message:"User no longer exists."});
        }

        const newAccessToken = generateToken(user._id, user.role, "15m");
        const newRefreshToken = crypto.randomBytes(40).toString("hex");

        await Session.create({
            userId:user._id,
            refreshToken:newRefreshToken,
            deviceInfo:session.deviceInfo,
            ip:session.ip,
            expiry: new Date(Date.now() + 7*24*60*60*1000) //7 days
        })

        await Session.deleteOne({_id:session._id});

        return res.status(200).json({
            message:"Tokens refreshed successfully",
            accessToken: newAccessToken,
            refreshToken: newRefreshToken
        });
    } catch (error) {
        console.log("Error in refresh token route:", error.message);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export const logout = async(req, res) => {
    const {refreshToken} = req.body;

    try {
        if(!refreshToken){
            return res.status(400).json({ message: "Refresh token required" });
        }

        const session = await Session.findOne({refreshToken});
        if(!session){
            return res.status(200).json({ message: "Already logged out" });
        }

        await Session.deleteOne({_id:session._id});
        return res.status(200).json({
            message: "Logged out successfully",
        });

    } catch (error) {
        console.log("Error in logout:", error.message);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export const logoutAllDevices = async(req,res)=>{
    try {
        const userId = req.user.userId;
        await Session.deleteMany({userId});
        return res.status(200).json({
            message: "Logged out from all devices",
        });
    }
    catch (error) {
        console.log("Error in logout all:", error.message);
        return res.status(500).json({ message: "Internal server error" });
    }
};

export const listSessions = async(req, res) => {
    try {
        const userId = req.user.userId;
        const sess = await Session.find({userId}).select("-refreshToken").sort({createdAt : -1});
        return res.status(200).json({sess});
    } catch (error) {
        console.log("Error listing sessions:", error.message);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export const revokeSession = async(req, res)=>{
    try {
        const userId = req.user.userId;
        const {sessionId} = req.params;

        if(!mongoose.Types.ObjectId.isValid(sessionId)){
            return res.status(400).json({ message: "Invalid session ID" });
        }

        const session = await Session.find({_id:sessionId,userId});
        if(!session){
            return res.status(404).json({message : "Session not found"});
        }

        await Session.deleteOne({ _id: sessionId });

        return res.status(200).json({
            message: "Session revoked successfully",
        });
    } catch (error) {
        console.log("Error revoking session:", error.message);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export const forgetPassword = async(req, res)=>{
    const{email} = req.body;
    try {
        if(!email){
            return res.status(400).json({message:"Email is required"});
        }
        const user = await User.findOne({email:email.toLowerCase()});
        if(!user){
            return res.status(200).json({
                message:"Reset link has been sent to registered email!"
            });
        }

        const resetToken = crypto.randomBytes(32).toString("hex");
        const key = `pswdreset:${user._id}`;

        await redis.set(key, resetToken, {
            ex: 900
        });

        console.log("DEV reset token", resetToken);

        return res.status(200).json({
            message:"Reset link has been sent to registered email!",
            devResetToken : resetToken,
            userId : user._id,
        })

    } catch (error) {
        console.log("Forgot password error:", error.message);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export const resetPassword = async(req, res) => {
    const{userId, token, newPassword} = req.body;
    try {
        if(!userId || !token || !newPassword){
            return res.status(400).json({message:"All fields are required"});
        }
        if(newPassword.length < 6){
            return res.status(400).json({message:"Password must contain at least 6 characters!"});
        }
        const key = `pswdreset:${userId}`;
        const storedToken = await redis.get(key);

        if(!storedToken || storedToken !== token){
            return res.status(400).json({message:"Invalid or expired reset token"});
        }

        const user = await User.findById(userId);
        if(!user){
            return res.status(400).json({ message: "User not found" });
        }

        const hashedPassword = await bcrypt.hash(newPassword,10);

        user.password = hashedPassword;
        await user.save();

        await redis.del(key);

        await Session.deleteMany({userId});
        await resetLoginFailures(user.email);
        return res.status(200).json({
            message: "Password reset successful. Please login again.",
        });
    } catch (error) {
        console.log("Reset password error:", error.message);
        return res.status(500).json({ message: "Internal server error" });
  }
}