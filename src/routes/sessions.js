import { Router } from 'express';
import jwt from 'jsonwebtoken';
import userModel from '../dao/models/users.js';
import { createHash } from '../utils.js'
import passport from "passport";
import config from '../config/config.js';

const ADMIN_EMAIL = config.adminEmail;

const router = Router();

router.post('/register', async (req, res) => {
    try {
        const { first_name, last_name, email, age, password } = req.body;

        // Verifica los campos obligatorios en la solicitud.
        if (!first_name || !last_name || !email || !password) {
            return res.status(400).json({ status: "error", error: "Missing required fields" });
        }

        // Verifica si el "email" coincide con el usuario local "ADMIN_EMAIL"
        if (email === ADMIN_EMAIL) {
            return res.status(400).json({ status: "error", error: "User already exists" });
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

router.post('/login', (req, res, next) => {
    passport.authenticate('login', (err, user, info) => {
        if (err) {
            return res.status(500).json({ message: 'Internal Server Error' });
        }
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        req.logIn(user, (loginErr) => {
            if (loginErr) {
                return res.status(500).json({ message: 'Login Error' });
            }
            delete req.user.password;
            // Inicia una sesión de usuario.
            req.session.user = {
                name: `${req.user.first_name} ${req.user.last_name}`,
                email: req.user.email,
                role: req.user.role
            }
            const userRole = req.user.role;
            const userEmail = req.user.email;

            // Genera un token JWT
            const token = jwt.sign({ email: userEmail, role: userRole }, "t0k3nJwtS3cr3t", {
                expiresIn: '1h', // Tiempo de expiración de 1 hora
            });

            // Establece la cookie 'access_token'
            return res
                .cookie("access_token", token, {
                    httpOnly: true,
                })
                .status(200)
                .json({ status: "success", payload: req.session.user, message: "Logged in successfully" });
        });
    })(req, res, next);
});

router.get('/github', passport.authenticate('github', { scope: ['user:email'] }), async (req, res) => { })

router.get('/githubCallback', passport.authenticate('github', { failureRedirect: '/loginFailed' }), async (req, res) => {
    // req.session.user = req.user;
    req.session.user = {
        name: `${req.user.email} - Github`,
        email: `${req.user.email} - (username)`,
        role: req.user.role
    }
    const userRole = req.user.role;
    const userEmail = req.user.email;

    // Genera un token JWT
    const token = jwt.sign({ email: userEmail, role: userRole }, "t0k3nJwtS3cr3t", {
        expiresIn: '1h', // Tiempo de expiración de 1 hora
    });

    // Establece la cookie 'access_token'
    res.cookie("access_token", token, {
        httpOnly: true,
    });

    // Redirige al usuario a '/products'
    res.redirect('/products');
})

router.get('/failLogin', (req, res) => {
    console.log("Entrando en failLogin");
    return res.status(500).json({ message: 'Login Error' });
})


export default router;
