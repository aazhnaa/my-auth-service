import jwt from "jsonwebtoken";
import {redis} from '../lib/redis.js';

export const rateLimiter = ({windowInSeconds, maxRequests, keyPrefix}) =>{
    return async(req, res, next) =>{
        try {
            //IP-based for unauthenticated users, User-based for authenticated users
            const identifier = req.user?.userId || req.ip;
            const key = `${keyPrefix}:${identifier}`;
            const currCount = await redis.incr(key);

            // First request → set expiry for the counter
            if(currCount === 1){
                await redis.expire(key, windowInSeconds);
            }

            if(currCount > maxRequests){
                return res.status(429).json({message : "Too many requests. Please try again later. "});
            }

            next();
        } catch (error) {
            console.log("Rate limiter error : ", error);
            next();
        }
    }
}
export const userMiddleware = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if(!authHeader || !authHeader.startsWith("Bearer ")){
            return res.status(401).json({message:"authorization token missing"});
        }

        const token = authHeader.split(" ")[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        req.user = {
            userId : decoded.userId,
            role : decoded.role
        }

        next();
    } catch (error) {
        return res.status(401).json({ message: "Invalid or expired access token"});
    }
}