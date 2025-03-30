import { Cart } from "../models/cartModel.js";
import { Product } from "../models/productModel.js";
import tryCatch from "../utils/tryCatch.js";


export const addToCart = tryCatch(async (req, res) => {
    const { product, quantity } = req.body

    if (!product) {
        return res.status(400).json({
            message: "Product ID is required",
        });
    }

    const cartProduct = await Product.findById(product);
    console.log("Product Details:", cartProduct)
    if (!cartProduct) {
        return res.status(404).json({
            message: "Product not found",
        });
    }
    const category = cartProduct.category;
    console.log(category)

    const cart = await Cart.findOne({
        product: product,
        user: req.user._id
    }).populate("product")

    if (cart) {
        if (cart.product.stock === cart.quantity) {
            return res.status(400).json({
                message: "Out of Stock",
            });
        }
        cart.quantity = cart.quantity + 1;
        await cart.save();
        return res.json({
            message: "Added to cart",
            cart
        })

    }
    else {
        if (cartProduct.stock === 0) {
            return res.status(400).json({
                message: "Out of Stock",
            });
        }
        const newCartItem = await Cart.create({
            quantity: 1,
            product: product,
            user: req.user._id
        })
        res.json({
            message: "Added to Cart",
            cart: newCartItem
        })
    }


})
export const removeFromCart = tryCatch(async (req, res) => {
    const cart = await Cart.findById(req.params.id)

    await cart.deleteOne()

    res.json({
        message: "Removed from cart"
    })

})
export const updateCart = tryCatch(async (req, res) => {
    const { action } = req.query;

    if (action === 'increment') {
        const { id } = req.body;
        const cart = await Cart.findById(id).populate("product");

        if (cart.quantity < cart.product.stock) {
            cart.quantity++;
            await cart.save();
        } else {
            return res.status(400).json({
                message: "Out of Stock"
            })
        }

        res.json({
            message: "Cart updated"
        })
    }

    if (action === "decrement") {
        const { id } = req.body;
        const cart = await Cart.findById(id).populate("product");

        if (cart.quantity > 1) {
            cart.quantity--;
            await cart.save();

        } else {
            return res.status(400).json({
                message: "You have only one item"
            })
        }
        res.json({
            message: "Cart updated"
        })
    }

})
export const fetchCart = tryCatch(async (req, res) => {

    const cart = await Cart.find({user: req.user._id}).populate("product")

    const totalQuantity = cart.reduce(
        (total, item) => total + item.quantity, 0
    )
    let subTotal = 0

    cart.forEach((i) => {
        const itemSubTotal = i.product.price * i.quantity;
        subTotal += itemSubTotal;
    })

    res.json({cart, subTotal, totalQuantity})
})
