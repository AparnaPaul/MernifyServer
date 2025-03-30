import mongoose from "mongoose";

const orderSchema = new mongoose.Schema(
  {
    items: [
      {
        quantity: {
          type: Number,
          required: true,
        },
        product: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "productModel",
          required: true,
        },
      },
    ],

    method: {
      type: String,
      required: true,
    },

    paymentInfo: {
      type: String,
    },

    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "userModel",
      required: true,
    },

    phone: {
      type: String,
      required: true,
    },

    address: {
      type: String,
      required: true,
    },

    status: {
      type: String,
      default: "Pending",
    },

    paidAt: {
      type: String,
    },

    subTotal: {
      type: Number,
      required: true,
    },
  },
  {
    timestamps: true,
  }
);

export const Order = mongoose.model("orderModel", orderSchema);