import { Router } from 'express';
import jwt from 'jsonwebtoken';
import passport from "passport";


const router = Router();

router.post('/register', (req, res, next) => {
    passport.authenticate('register', (err, user, info) => {
        if (err) {
            console.error("Error de registro:", err);
            return res.status(500).json({ status: "error", error: "Internal Server Error" });
        }
        if (!user) {
            return res.status(400).json({ status: "error", error: info.message });
        }
        // Si el usuario se ha registrado con éxito
        return res.status(200).json({ status: "success", message: "User registered" });
    })(req, res, next);
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
