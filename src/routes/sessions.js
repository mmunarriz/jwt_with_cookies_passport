import { Router } from 'express';
import jwt from 'jsonwebtoken';
import userModel from '../dao/models/users.js';
import requireAuth from '../controllers/auth.js';
import { createHash, isValidPassword } from '../utils.js'
import config from '../config/config.js';

const ADMIN_EMAIL = config.adminEmail
const ADMIN_PASSWORD = config.adminPassword

const router = Router();

router.post('/register', async (req, res) => {
    try {
        const { first_name, last_name, email, age, password } = req.body;

        // Verifica los campos obligatorios en la solicitud.
        if (!first_name || !last_name || !email || !password) {
            return res.status(400).json({ status: "error", error: "Missing required fields" });
        }

        // Verifica si el "email" ya existe en la DB
        const exists = await userModel.findOne({ email });
        if (exists) {
            return res.status(400).json({ status: "error", error: "User already exists" });
        }

        // Crea el usuario en la DB
        const user = {
            first_name,
            last_name,
            email,
            age,
            password: createHash(password)
        }
        const result = await userModel.create(user);
        return res.status(200).json({ status: "success", message: "User registered" });
    } catch (error) {
        console.error("User registration error:", error);
        return res.status(500).json({ status: "error", error: "Internal Server Error" });
    }
});

router.post("/login", async (req, res) => {
    const { email, password } = req.body;

    // Comprueba si los datos coinciden con estos.
    if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
        // Inicia una sesión de usuario Administrador.
        req.session.user = {
            name: "Admin Coderhouse",
            email: email,
            rol: "admin"
        }
        const userRole = "admin";
        // Genera un token JWT y establece la cookie.
        const token = jwt.sign({ email, rol: userRole }, "t0k3nJwtS3cr3t", {
            expiresIn: '1h', // Tiempo de expiración de 1 hora
        });

        return res
            .cookie("access_token", token, {
                httpOnly: true,
            })
            .status(200)
            .json({ status: "success", payload: req.session.user, message: "Logged in successfully" });
    }

    // Si no coinciden los datos locales, verifica en la base de datos.
    try {
        // Busca el usuario en la base de datos.
        const user = await userModel.findOne({ email });

        if ((!user) || (!isValidPassword(user, password))) {
            return res.status(401).json({ message: "Invalid credentials" });
        }

        // Inicia una sesión de usuario.
        req.session.user = {
            name: `${user.first_name} ${user.last_name}`,
            email: user.email,
            rol: user.role
        }

        const userRole = user.role;
        // Genera un token JWT y establece la cookie.
        const token = jwt.sign({ email, rol: userRole }, "ECOMMERCE_SECRET_KEY", {
            expiresIn: '1h', // Tiempo de expiración de 1 hora
        });

        return res
            .cookie("access_token", token, {
                httpOnly: true,
            })
            .status(200)
            .json({ status: "success", payload: req.session.user, message: "Logged in successfully" });

    } catch (error) {
        // Maneja errores en la base de datos.
        console.error(error);
        return res.status(500).json({ message: "Internal server error" });
    }
});


export default router;
