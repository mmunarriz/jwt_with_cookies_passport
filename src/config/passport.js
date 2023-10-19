import passport from 'passport';
import local from "passport-local"
import userModel from '../dao/models/users.js';
import { createHash, isValidPassword } from '../utils.js';
import config from '../config/config.js';
import gitHubStrategy from "passport-github2"


const ADMIN_EMAIL = config.adminEmail;
const ADMIN_PASSWORD = config.adminPassword;

const LocalStrategy = local.Strategy;
const GitHubStrategy = gitHubStrategy.Strategy;
export const initializePassport = () => {
    passport.use('register', new LocalStrategy({ passReqToCallback: true, usernameField: 'email' }, async (req, username, password, done) => {
        const { first_name, last_name, email, age } = req.body;
        try {
            const exists = await userModel.findOne({ email: username });
            if (exists) {
                console.log('El usuario ya existe')
                return done(null, false);
            };
            const newUser = {
                first_name,
                last_name,
                email,
                age,
                password: createHash(password)
            };
            let result = await userModel.create(newUser);
            return done(null, result)
        } catch (error) {
            return done('Error al crear el usuario:' + error)
        }
    }));

    passport.use('login', new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
        try {
            if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
                const user = {
                    _id: "000000000000000000000000", // Simulado para que funcione 'passport.serializeUser'
                    first_name: "Admin",
                    last_name: "Coderhouse",
                    email: email,
                    role: "admin"
                };
                return done(null, user);
            }
            const user = await userModel.findOne({ email });
            if (!user) {
                console.log("No existe el usuario en la DB")
                return done(null, false);
            }
            if (!isValidPassword(user, password)) {
                return done(null, false);
            }
            return done(null, user);
        } catch (error) {
            return done('Login error:' + error)
        }
    }));

    passport.use('github', new GitHubStrategy({
        clientID: "Iv1.e6e683b54218aebb",
        clientSecret: "b8c8a24be25cf56f74a3cb73b0005e002f8122e1",
        callBackURL: "http://localhost:8080/api/sessions/githubCallback"
    }, async (accessToken, refreshToken, profile, done) => {
        try {

            console.log(profile);
            let user = await userModel.findOne({ email: profile.username })
            if (!user) {
                // Crear el usuario en la DB si no existe 
                let newUser = { email: profile.username, password: " ", role: "github_user" }
                let result = await userModel.create(newUser);
                return done(null, result);
            }
            return done(null, user)
        } catch (error) {
            return done(error)
        }
    }));

    passport.serializeUser((user, done) => {
        done(null, user._id)
    })

    passport.deserializeUser(async (id, done) => {
        let user = await userModel.findById(id);
        done(null, user);
    })
}