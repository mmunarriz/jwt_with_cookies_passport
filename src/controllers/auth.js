import jwt from 'jsonwebtoken';

const authorization = (req, res, next) => {
    const token = req.cookies.access_token;
    if (!token) {
        return res.redirect('/login');
    }
    try {
        const data = jwt.verify(token, "t0k3nJwtS3cr3t");
        req.userEmail = data.email;
        req.userRole = data.role;
        return next();
    } catch {
        return res.redirect('/login');
    }
};

export default authorization;
