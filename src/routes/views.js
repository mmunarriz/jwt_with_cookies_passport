import { Router } from 'express';
import productsModel from "../dao/models/products.js";
import requireAuth from "../controllers/auth.js"

const router = Router();

// Ruta protegida: (solo accesible si el usuario no está autenticado)
router.get('/register', (req, res) => {
    if (req.session.user) {
        return res.redirect('/profile'); // Redirige al usuario autenticado a su perfil si intenta acceder al 'register'
    }
    res.render('register');
});

// Ruta protegida: (solo accesible si el usuario no está autenticado)
router.get('/login', (req, res) => {
    if (req.session.user) {
        return res.redirect('/profile'); // Redirige al usuario autenticado a su perfil si intenta acceder al 'login'
    }
    res.render('login');
});

// Ruta requiere estar autenticado
router.get("/logout", requireAuth, (req, res) => {
    // Accede al ID de la sesión desde la sesión actual
    const sessionId = req.sessionID;

    // Destruye la sesión actual en la base de datos MongoDB Atlas
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session in MongoDB:', err);
            return res.status(500).json({ message: "Internal server error" });
        }

        // Elimina la cookie con el token JWT
        res.clearCookie("access_token");

        // Elimina la cookie "connect.sid"
        res.clearCookie("connect.sid");

        // Respuesta exitosa
        // return res.status(200).json({ message: "Successfully logged out" });
        res.redirect("/login")
    });
});

// Ruta de acceso libre
router.get('/', (req, res) => {
    res.render('login', {
        user: req.session.user
    });
})

// Ruta de acceso libre
router.get('/home', (req, res) => {
    res.render('home', {
        user: req.session.user
    });
})

// Ruta requiere estar autenticado
router.get('/profile', requireAuth, (req, res) => {
    res.render('profile', {
        user: req.session.user
    });
})

// Ruta requiere estar autenticado
router.get('/products', requireAuth, async (req, res) => {
    const { page = 1 } = req.query;
    const { docs, hasPrevPage, hasNextPage, nextPage, prevPage } = await productsModel.paginate({}, { limit: 8, page, lean: true });
    const products = docs;
    res.render('products', {
        user: req.session.user,
        products,
        hasPrevPage,
        hasNextPage,
        prevPage,
        nextPage
    });
})

// Ruta requiere estar autenticado
router.get('/current', requireAuth, (req, res) => {
    res.render('current', {
        user: req.session.user
    });
})

export default router;