import { Address } from "../models/addressModel.js";
import tryCatch from "../utils/tryCatch.js";

export const addAddress = tryCatch(async (req, res) => {
    const { address, phone } = req.body;

    await Address.create({
        address,
        phone,
        user: req.user._id
    })

    res.status(201).json({
        message: "Address created"
    })
})

export const getAllAddress = tryCatch(async (req, res) => {
    const allAddress = await Address.find({ user: req.user._id });
    res.json(allAddress)
})

export const getSingleAddress = tryCatch(async (req, res) => {
    const address = await Address.findById(req.params.id);

    res.json(address);
})

export const deleteAddress = tryCatch(async (req, res) => {
    const address = await Address.findOne({
        _id: req.params.id,
        user: req.user._id
    })
    await address.deleteOne();
    res.json({
        message: "Address deleted"
    })
})