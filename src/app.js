import express from 'express';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import mongoose from 'mongoose';
import handlebars from 'express-handlebars';
import __dirname from './utils.js';
import cookieParser from 'cookie-parser';
import config from './config/config.js';
import sessionsRouter from './routes/sessions.js';
import viewsRouter from './routes/views.js';


const MONGO_URL = config.mongoUrl
const PORT = config.port

const app = express();
app.use(cookieParser());
const connection = mongoose.connect(MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname + '/public'))
app.use(session({
    store: new MongoStore({
        mongoUrl: MONGO_URL,
        ttl: 3600
    }),
    secret: "3c0mm3rc3l0g1n",
    resave: false,
    saveUninitialized: false
}))

app.engine('handlebars', handlebars.engine());
app.set('views', __dirname + '/views');
app.set('view engine', 'handlebars');

app.use('/', viewsRouter);
app.use('/api/sessions', sessionsRouter);
// catch all route
app.get("*", (req, res) => {
    res.send('Error 404 - Not Found');
});

const server = app.listen(PORT, () => console.log("Listening on port " + PORT))
