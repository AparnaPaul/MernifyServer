import mongoose from "mongoose";

const addressSchema = new mongoose.Schema({
    // street: {
    //     type: String,
    //     required: true
    // },
    // city: {
    //     type: String,
    //     required: true
    // },
    // state: {
    //     type: String,
    //     required: true
    // },
    // zipcode: {
    //     type: String,
    //     required: true
    // },
    // country: {
    //     type: String,
    //     required: true
    // },
    address: {
        type: String,
        required : true
    },
    phone: {
        type: String,
        required: true
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "userModel",
        required: true
    }
})

export const Address = mongoose.model("addressModel", addressSchema);