'use strict';
require('dotenv').config();
const express = require('express');
const cookieSession = require('cookie-session');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { randomHex32String } = require('./helpers');
const userRouter = require('./controllers/user');
const app = express();

app.use(express.json({}));

app.use(cookieSession({
	name: 'seesion',
	keys: [randomHex32String()],
	maxAge: 24*60*60*1000
}));

app.use(cookieParser());
app.use(cors({
	origin: 'http://localhost:3000',
	credentials: true
}));

app.use(express.static('dist'));

app.get('/', (req, res) => {
	res.send('Express server is up and running');
});

app.use('/webauthn', userRouter);
const port = process.env.PORT || 8080;

app.listen(port, () => {
	console.log('Server listening on http://localhost:' + port);
});
