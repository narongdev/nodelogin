const express = require('express');
const path = require('path');
const cookieSession = require('cookie-session');
const bcrypt = require('bcrypt');
const dbConnection = require('./database');
const {body, validationResult} = require('express-validator');

const app = express();
app.use(express.urlencoded({ extended: false }));

app.set('views', path.join(__dirname, './view'));
app.set('view engine', 'ejs');
app.use(cookieSession({
    name: 'session',
    keys: ['key1','key2'],
    maxAge: 3600 * 1000 // 1 hr
}));

// Middleware 
const ifNotLoggedIn = (req, res, next) => {
    if(!req.session.isLoggedIn){
        return res.render('login')
    }
    next(); 
}
const ifLoggedIn = (req, res, next) => {
    if(req.session.isLoggedIn){
        return res.render('home')
    }
    next();
}

// Register
app.post('/register' , ifLoggedIn, [
    body('r_email', 'Invalid Email').isEmail().custom((value) => {
        return dbConnection.execute('SELECT email FROM accounts WHERE email=?', [value])
        .then(([rows]) => {
            if(rows.length > 0){
                return Promise.reject('This email already in used');
            }
            return true;
        })
    }),
    body('r_username', 'Username is empty').trim().not().isEmpty(),
    body('r_password', 'Must be minimum 6 characters ').trim().isLength({min:5})
], // end of validate

(req, res) => {
    const validation_result = validationResult(req);
    const { r_username, r_password, r_email } = req.body;

    if(validation_result.isEmpty()){
        bcrypt.hash(r_password, 12).then((hash_pass) => {
            dbConnection.execute('INSERT INTO accounts (username,password,email) VALUES (?, ?, ?)',[r_username, hash_pass, r_email])
            .then(results => {
                res.send(`Created successfully, You can <a href="/login">Login</a>`);
            })
            .catch(err => {
                if(err) throw err;
            })
        }).catch(err => {
            if(err) throw err;
        })
    }else{
        let allErrors = validation_result.errors.map((error)=>{
            return error.msg;
        })
        res.render('login', {
            register_error: allErrors,
            old_data: req.body
        })
    }
})


// Root page
app.get('/' , ifNotLoggedIn, (req , res, next)=>{

    dbConnection.execute('SELECT username FROM accounts WHERE id=?',[req.session.userID])
    .then(([rows]) => {
        res.render('home',{
            username:rows[0].username
        })
    })

})

// Login Page
app.get('/login' , (req , res)=>{
    //res.render('login');
    res.redirect('/');
})

// Login Auth
app.post('/' , ifLoggedIn, [
    body('username').custom((value)=>{
        return dbConnection.execute('SELECT username FROM accounts WHERE username=?',[value])
        .then(([rows]) => {
            if(rows.length==1){
                return true;
            }
            return Promise.reject('Invalid Username')
        })
    }),
    body('password', 'Password is empty').trim().not().isEmpty()
],
(req, res)=>{
    const validation_result = validationResult(req);
    const { username, password } = req.body;
    if(validation_result.isEmpty()){
        dbConnection.execute('SELECT * FROM accounts WHERE username=?', [username])
        .then(([rows])=>{
            bcrypt.compare(password, rows[0].password)
            .then(compare_result=>{
                if(compare_result===true){
                    req.session.isLoggedIn = true;
                    req.session.userID = rows[0].id;
                    res.redirect('/');
                }else{
                    res.render('login', {
                        login_errors : ['Invalid Password'],
                        old_data: req.body
                    })
                }
            }).catch(err => {
                if(err) throw err;
            })
        }).catch(err => {
            if(err) throw err;
        })
    }else{
        let allErrors = validation_result.errors.map((error)=>{
            return error.msg;
        })
        res.render('login', {
            login_errors: allErrors,
            old_data: req.body
        })
    }
})

// Logout
app.get('/logout' , (req , res)=>{
    req.session = null;
    res.redirect('/');
})

// 404 Page Not found
app.use('/', (req, res) => {
    res.status(404).send('<h1>404 Page Not Found !</h1>')
})

app.listen(3000, () => console.log('Server in running...'));