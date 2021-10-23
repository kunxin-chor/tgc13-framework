const express = require('express')
const hbs = require('hbs')
const wax = require('wax-on') // for {{#extends}} {{#block}}
require('dotenv').config();
const session = require('express-session');
const flash = require('connect-flash');
const FileStore = require('session-file-store')(session);
const csrf = require('csurf');
const cors = require('cors');

// Create an express application
let app = express(); 


// set the view engine
app.set('view engine', 'hbs');

// set the static folder (we find browser-based JavaScript, css files and images)
app.use(express.static('public'))

// setup handlebars to use wax-on (so that we can use template inheritance)
wax.on(hbs.handlebars);
// tell wax-on where to find the layout files
wax.setLayoutPath('./views/layouts')

// enable forms
app.use(express.urlencoded({
    extended: false
}))

// Cors must be enabled before session
app.use(cors())

// setup sessions
app.use(session({
    'store': new FileStore(),
    'secret': process.env.SESSION_SECRET_KEY,
    'resave': false,
    'saveUninitialized': true
}))



// setup flash
app.use(flash())

// register flash middleware to display the flashed messages inside our hbs files
app.use(function(req,res,next){
    // we are adding to the hbs template variables named
    // success_messages and error_messages
    // they will be assigned the values of the flashed messages 'success_messages' and 'error_messages'
    res.locals.success_messages = req.flash('success_messages');
    res.locals.error_messages = req.flash('error_messages')
    next();
})

// enable protection from cross site request forgery
// app.use(csrf());
const csurfInstance = csrf();
app.use(function(req,res,next){
    // we are exlcuding csrf for /checkout/process_payment and any routes which path 
    // begins with '/api/'
    if (req.url == "/checkout/process_payment" || req.url.slice(0,5) == '/api/') {
        return next();
    } else {
        // manually called the csurfInstance to 
        // check the request
        csurfInstance(req,res,next)
    }
})

// middleware to inject the csrf token into all hbs files
app.use(function(req, res, next){
    if (req.csrfToken) {
        res.locals.csrfToken = req.csrfToken();
    }    
    next();
})

// share the user data with all hbs files
app.use(function(req,res,next){
    res.locals.user = req.session.user;
    next(); // call the next middleware, or the route
            // if no middleware left
})

app.options('*', cors()) // include before other routes

const landingRoutes = require('./routes/landing')
const productRoutes = require('./routes/products')
const userRoutes = require('./routes/users')
const cloudinaryRoutes = require('./routes/cloudinary')
const cartRoutes = require('./routes/cart')
const checkoutRoutes = require('./routes/checkout')


const api = {
    'products': require('./routes/api/products'),
    'users': require('./routes/api/users')
}

async function main() {

    app.use('/', landingRoutes);
    app.use('/products', productRoutes);
    app.use('/users', userRoutes);
    app.use('/cloudinary', cloudinaryRoutes);
    app.use('/cart', cartRoutes);
    app.use('/checkout', checkoutRoutes);
    app.use('/api/products', [express.json()], api.products);
    app.use('/api/users', [express.json()], api.users);
}

main();

app.listen(3000, function(){
    console.log("Server has started")
})