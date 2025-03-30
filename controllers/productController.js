import { Product } from "../models/productModel.js";
import bufferGenerator from "../utils/bufferGenerator.js";
import tryCatch from "../utils/tryCatch.js";
import cloudinary from 'cloudinary';


export const createProduct = tryCatch(async (req, res) => {
    console.log("Request Body:", req.body);  // Add this line for debugging
    if (!req.admin || req.admin.role !== "admin") {
        return res.status(403).json({ message: "You are not admin" });
    }

    const { title, description, category, price, stock } = req.body
    if (!title || !description || !category || !price || !stock) {
        return res.status(400).json({
            message: "Title, description, category, price, and stock are required",
        });
    }
    const files = req.files

    if (!files || files.length === 0) {
        return res.status(400).json({
            message: "No files to upload"
        })
    }
    const imageUploadPromises = files.map(async (file) => {
        const fileBuffer = bufferGenerator(file)

        const result = await cloudinary.v2.uploader.upload(fileBuffer.content)
        return {
            id: result.public_id,
            url: result.secure_url
        }
    })

    const uploadedImage = await Promise.all(imageUploadPromises)
    const product = await Product.create({
        title,
        description,
        category,
        price,
        stock,
        images: uploadedImage
    })

    res.status(201).json({
        message: "Product Created",
        product
    })


})

export const getAllProducts = tryCatch(async (req, res) => {
    const { search, category, page, sortByPrice } = req.query;
    const filter = {}

    if (search) {
        filter.title = {
            $regex: search,
            $options: "i",
        }
    }

    if (category) {
        filter.category = category;

    }

    const limit = 8
    const skip = (page - 1) * limit

    let sortOption = { createdAt: -1 }

    if (sortByPrice) {
        if (sortByPrice === "lowToHigh") {
            sortOption = { price: 1 }
        } else if (sortByPrice === "highToLow") {
            sortOption = { price: -1 }
        }
    }
    const products = await Product.find(filter)
        .sort(sortOption)
        .limit(limit)
        .skip(skip)

    const categories = await Product.distinct("category")

    const newProduct = await Product.find().sort("-createdAt").limit(4)

    const countProduct = await Product.countDocuments()

    const totalPages = Math.ceil(countProduct / limit);

    res.json({ products, categories, totalPages, newProduct })
})

export const getSingleProduct = tryCatch(async (req, res) => {
    const { id } = req.params;

    // Log the product ID
    console.log("Product ID:", id);

    // Find the product in the database
    const product = await Product.findById(id);
    console.log("Product Details:", product);
    if (!product) {
        return res.status(404).json({
            message: "Product not found",
        });
    }

    // const product = await Product.findById(req.params.id)

    const relatedProduct = await Product.find({
        category: product.category,
        _id: { $ne: product._id }
    }).limit(4);

    res.json({ product, relatedProduct })
})

export const updateProduct = tryCatch(async (req, res) => {
    if (!req.admin || req.admin.role !== "admin") {
        return res.status(403).json({ message: "You are not admin" });
    }

    const { title, description, category, price, stock } = req.body

    const updateFields = {}

    if (title) {
        updateFields.title = title
    }
    if (description) updateFields.description = description;
    if (stock) updateFields.stock = stock;
    if (price) updateFields.price = price;
    if (category) updateFields.category = category;

    const updatedProduct = await Product.findByIdAndUpdate(
        req.params.id,
        updateFields,
        { new: true, runValidators: true })

    if (!updatedProduct) {
        return res.status(404).json({
            message: "Product not found",
        })
    }
    res.json({
        message: "Product updated",
        updatedProduct
    })

})

export const updateProductImage = tryCatch(async (req, res) => {
    if (!req.admin || req.admin.role !== "admin") {
        return res.status(403).json({ message: "You are not admin" });
    }

    const { id } = req.params
    const files = req.files
    if (!files || files.length === 0) {
        return res.status(400).json({
            message: "No files to upload"
        })
    }

    const product = await Product.findById(id)

    if (!product) {
        return res.status(404).json({
            message: "Product not found",
        })
    }

    const oldImages = product.images || [];

    for (const img of oldImages) {
        if (img.id) {
            await cloudinary.v2.uploader.destroy(img.id);
        }
    }
    const imageUploadPromises = files.map(async (file) => {
        const fileBuffer = bufferGenerator(file)

        const result = await cloudinary.v2.uploader.upload(fileBuffer.content)
        return {
            id: result.public_id,
            url: result.secure_url
        }
    })

    const uploadedImage = await Promise.all(imageUploadPromises);
    product.images = uploadedImage;
    await product.save();

    res.status(200).json({
        message: "Image updated",
        product
    })
})