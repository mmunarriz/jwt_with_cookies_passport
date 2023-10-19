import mongoose from 'mongoose';

const cartCollection = 'carts';

const cartsSchema = mongoose.Schema({
    products: [
        {
            product: {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'products' // Nombre del modelo de productos
            },
            quantity: {
                type: Number,
                default: 0,
            },
        },
    ],
});

const cartsModel = mongoose.model(cartCollection, cartsSchema);
export default cartsModel;
