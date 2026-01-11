import jwt from "jsonwebtoken";

export const generateToken = (userId, userRole, expiry, res) =>{
    const token = jwt.sign({userId, role:userRole}, process.env.JWT_SECRET,{expiresIn:`${expiry}`});

    // res.cookie("jwt",token,{
    //     maxAge : 7 * 24 * 60 * 60 * 1000,
    //     httpOnly : true, 
    //     sameSite:"strict",
    //     secure: process.env.NODE_ENV !== "development"
    // })

    return token;
}