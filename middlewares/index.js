const jwt = require('jsonwebtoken')

const checkIfAuthenticated = function(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        req.flash("error_messages", "You must log in to view this page");
        res.redirect('/users/login');
    }
}

function checkIfAuthenticatedJWT(req,res,next) {
    // extract the header from the request 
    // if we use const to declare a variable it means that we don't intend
    // to reassign it
    const authHeader = req.headers.authorization;
    console.log("Header=", req.headers);
    console.log("AuthHeader=",authHeader);
    if (authHeader) {
        // try to get the access token
        const token = authHeader.split(' ')[1];

        // we use jwt to verify
        jwt.verify(token, process.env.TOKEN_SECRET, function(err, payload){
            // if err is not null or undefined
            if (err){
                return res.sendStatus(403);
            }
            req.user = payload;
            next();

        })
    } else {
        return res.sendStatus(401);
    }

}



module.exports = {
    checkIfAuthenticated, checkIfAuthenticatedJWT
}