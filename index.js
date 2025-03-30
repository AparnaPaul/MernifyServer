import express from 'express';
import dotenv from "dotenv";
import connectDb from './utils/db.js';
import cloudinary from 'cloudinary';
import cors from 'cors';
import cookieParser from "cookie-parser"


dotenv.config();

cloudinary.v2.config({
    cloud_name: process.env.CLOUD_NAME,
    api_key: process.env.CLOUD_API_KEY,
    api_secret: process.env.CLOUD_API_SECRET 
});

const app = express();

app.use(
    cors({
      origin: "http://localhost:5173", 
      credentials: true, //  Important for sending cookies,
      methods: ["GET","POST","PUT", "DELETE"]
    })
  );

app.use(cookieParser())
app.use(express.json())

const port = process.env.PORT || 3000

//importing routes 
import userRoutes from './routes/userRoute.js'
import productRoutes from './routes/productRoute.js';
import adminRoutes from './routes/adminRoute.js';
import cartRoutes from './routes/cartRoute.js';
import orderRoutes from './routes/orderRoute.js';
import reviewRoutes from './routes/reviewRoute.js';
import addressRoutes from './routes/addressRoute.js'



//using routes
app.use("/api", userRoutes)
app.use("/api", productRoutes)
app.use("/api", adminRoutes)
app.use("/api", cartRoutes)
app.use("/api", addressRoutes )
app.use("/api", orderRoutes)
app.use("/api", reviewRoutes)


app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
    connectDb();
});