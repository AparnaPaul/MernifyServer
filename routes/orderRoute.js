import express from "express";
import {
  getAllOrders,
  getAllOrdersAdmin,
  getMyOrder,
  getReport,
  newOrderCod,
  updateStatus,
} from "../controllers/orderController.js";
import { isValidUser } from "../middlewares/isValidUser.js";
import { isValidAdmin } from "../middlewares/isValidAdmin.js";

const router = express.Router();


router.post("/order/new/cod", isValidUser, newOrderCod)
router.get("/order/all", isValidUser, getAllOrders);
router.get("/order/admin/all", isValidAdmin, getAllOrdersAdmin);
router.get("/order/:id", isValidUser, getMyOrder);
router.put("/order/:id", isValidAdmin, updateStatus);
router.get("/report", isValidAdmin, getReport);



export default router;