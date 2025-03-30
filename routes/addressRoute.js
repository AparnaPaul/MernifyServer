import express from 'express';
import { isValidUser } from '../middlewares/isValidUser.js';
import { addAddress, deleteAddress, getAllAddress, getSingleAddress } from '../controllers/addressController.js';

const router = express.Router();

router.post('/address/new', isValidUser, addAddress)
router.get('/address/all', isValidUser, getAllAddress)
router.get('/address/:id', isValidUser, getSingleAddress)
router.delete('/address/:id', isValidUser, deleteAddress)

export default router;
