import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    address: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "addressModel"

    },
    mobile: {
        type: String,
        required: true
    },
    role: {
        type: String,
        default: "user",
    },
},
    {
        timestamps: true
    }
)

export const User = mongoose.model("userModel", userSchema);