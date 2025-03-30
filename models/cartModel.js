import mongoose from "mongoose";

const cartSchema = new mongoose.Schema({
    quantity: {
      type: Number,
      required: true,
    },
  
    product: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "productModel",
      required: true,
    },
  
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "userModel",
      required: true,
    },
  });

export const Cart = mongoose.model("cartModel", cartSchema);