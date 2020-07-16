require('dotenv').config();
const express = require('express');
const app = express();
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

app.use(express.json());
app.use(express.static(path.join(__dirname+'/public')));

const mongoose = require('mongoose');
mongoose.connect(`mongodb+srv://${process.env.MONGO_LOGIN}:${process.env.MONGO_PASSWORD}@${process.env.MONGO_LINK}`, {useNewUrlParser: true, useUnifiedTopology: true});
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', function() {
  console.log('Connected to DB.');
});

const User = mongoose.model('User', { email: String, password: String, refreshToken: String });

app.get('/auth', (req, res)=>{res.sendFile(path.join(__dirname+'/index.html'))});

app.post('/auth/login', (req, res)=>{
    if(req.body.email==null || req.body.password==null){res.sendStatus(500)}
    const email = req.body.email;
    User.findOne({email}, async (err, user)=>{
        if(user==null){
            return sendStatus(400);
        }
        try{
            if(await bcrypt.compare(req.body.password, user.password)){
                console.log('OK');
                const accessToken = generateAccessToken(email);
                const refreshToken = jwt.sign(email, process.env.REFRESH_TOKEN_SECRET);
                user.refreshToken = refreshToken;
                await user.save();
                res.send({accessToken, refreshToken});
            }else{
                res.send('Login or password incorrect!');
            }
        }
        catch{
            res.send('Something wrong!');
        } 
    })  
})

function generateAccessToken(email){
    return jwt.sign({email: email}, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '45s'});
}

app.post('/auth/token', (req, res)=>{
    const refreshToken = req.body.token;
    if(refreshToken == null) return res.sendStatus(401);
    if(!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user)=>{
        if (err) return res.sendStatus(403);
        const accessToken = generateAccessToken({email: user.email});
        res.send({accessToken});
    })
})

app.delete('/auth/logout', (req, res)=>{
    refreshTokens = refreshTokens.filter((token)=>token!=req.body.token);
    res.sendStatus(204);
})

// app.post('/reg', async (req, res)=>{
//     try{
//         const hashedPassword = await bcrypt.hash(req.body.password, 10);
//         if(req.body.email != null && req.body.password != null){
//         const user = new User({email: req.body.email, password: hashedPassword});
//         user.save().then(()=>{res.sendStatus(200);})}
//         else res.sendStatus(500);
//     }
//     catch{
//         res.sendStatus(500);
//     }
// })

app.get('/auth/users', authenticateToken, async (req, res)=>{
    if(req.email!=null){
        User.find((err, users)=>{
            res.send(users);
        })
    }else {res.send('Auth require!')}
})

function authenticateToken(req, res, next){
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null){res.sendStatus(401)}
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, email)=>{
        req.email = email;
        next();
    })
}

app.listen(4000, function() {console.log('Listening on 4000');})