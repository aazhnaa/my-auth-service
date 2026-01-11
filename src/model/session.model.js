import mongoose from "mongoose";

const sessionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'User',
        index: true
    },
    refreshToken: {
        type: String,
        required: true,
        unique: true
    },
    deviceInfo: {
        type: String,
        default: "Unknown Device",
    },
    ip: {
        type: String,
        default: null
    },
    expiry: {
        type: Date,
        required: true,
        index: { expires: 0 }
    }
},
{
        timestamps: { createdAt: true, updatedAt: false },
    })

export default mongoose.model("Session", sessionSchema);