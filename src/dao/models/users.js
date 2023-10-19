import mongoose from 'mongoose';

const collection = 'users';

const schema = new mongoose.Schema({
    first_name: {
        type: String
    },
    last_name: {
        type: String
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    age: {
        type: Number,
        default: null
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        default: "user"
    },
    cart: [
        {
            _id: {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'carts.model' // Nombre del modelo de carts
            },
        },
    ],
})

const userModel = mongoose.model(collection, schema);

export default userModel;