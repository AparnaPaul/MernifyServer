import mongoose from "mongoose";

const reviewSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "userModel",
        required: true
    },
    productId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "productModel",
        required: true
    },
    rating: {
        type: Number,
        required: true,
        min: 1,
        max: 5
    },
    reviewComment: {
        type: String,
        required: true
    },
    reviewDate: {
        type: Date,
        default: Date.now
    }
},
    {
        timestamps: true
    });

export const Review = mongoose.model("reviewModel", reviewSchema);