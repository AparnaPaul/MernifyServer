import { Cart } from "../models/cartModel.js";
import { Order } from "../models/orderModel.js";
import { Product } from "../models/productModel.js";
import sendOrderConfirmation from "../utils/sendOrderConfirmation.js";
import tryCatch from "../utils/tryCatch.js";

export const newOrderCod = tryCatch(async (req, res) => {
    const { method, phone, address } = req.body

    const cart = await Cart.find({ user: req.user._id }).populate({
        path: "product",
        select: "title price",
    })

    if (!cart.length) {
        return res.status(400).json({
            message: "Cart is empty"
        })
    }

    let subTotal = 0;
    const items = cart.map((i) => {
        const itemSubTotal = i.product.price * i.quantity;

        subTotal += itemSubTotal;
        return {
            product: i.product._id,
            title: i.product.title,
            price: i.product.price,
            quantity: i.quantity
        }
    })

    const order = await Order.create({
        items,
        method,
        user: req.user._id,
        phone,
        address,
        subTotal
    });

    for (let i of order.items) {
        const product = await Product.findById(i.product)

        if (product) {
            product.stock -= i.quantity;
            product.sold += i.quantity;

            await product.save();

        }
    }

    await Cart.deleteMany({ user: req.user._id })

    await sendOrderConfirmation({
        email: req.user.email,
        subject: "Order Confirmation",
        orderId: order._id,
        products: items,
        totalAmount: subTotal
    })

    res.json({
        message: "Order created successfully",
        order
    })
})


export const getAllOrders = tryCatch(async (req, res) => {
    const orders = await Order.find({ user: req.user._id })

    res.json({
        orders: orders.reverse()
    })
})

export const getAllOrdersAdmin = tryCatch(async (req, res) => {
    if (req.user.role !== "admin") {
        return res.status(403).json({
            message: "You are not admin"
        })
    }

    const orders = await Order.find().populate("user").sort({
        createdAt: -1
    })
    res.json(orders);

})


export const getMyOrder = tryCatch(async (req, res) => {
    const order = await Order.findById(req.params.id).populate("items.product").populate("user")
    res.json(order);
})

export const updateStatus = tryCatch(async (req, res) => {
    if (req.user.role !== "admin") {
        return res.status(403).json({
            message: "You are not admin"
        })
    }

    const order = await Order.findById(req.params.id)

    const { status } = req.body
    order.status = status

    await order.save()
    res.json({
        message: "Order Status Updated",
        order
    })
})

export const getReport = tryCatch(async (req, res) => {
    if (req.user.role !== "admin") {
        return res.status(403).json({
            message: "You are not admin"
        })
    }

    const cod = await Order.find({ method: "cod" }).countDocuments();
    const online = await Order.find({ method: "online" }).countDocuments()

    const products = await Product.find()

    const data = products.map((product) => (
        {
            title: product.title,
            sold: product.sold

        }))

    res.json({
        cod,
        online,
        data
    })

})

