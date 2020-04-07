const express = require('express');
const cookieSession = require('cookie-session');
const cookieParser = require('cookie-parser');
const { randomHex32String } = require('./helpers');

const app = express();

app.use(express.json({}));

app.use(cookieSession({
	name: 'seesion',
	keys: [randomHex32String],
	maxAge: 24*60*60*1000
}));
app.use(cookieParser());

app.use(express.static('dist'));

app.get('/', (req, res) => {
	res.send('Express server is up and running');
});

app.listen(8080, () => {
	console.log('Server listening on http://localhost:8080');
});
