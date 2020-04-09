const mongoose = require('mongoose');
const dbPath = 'mongodb+srv://rootadmin:root1234@webauthn-6ypjt.mongodb.net/test?retryWrites=true&w=majority';
mongoose.connect(dbPath, {
	useNewUrlParser: true,
	useUnifiedTopology: true,
});
const db = mongoose.connection;
db.on('error', () => {
	console.log('> error occurred from the database');
});
db.once('open', () => {
	console.log('> successfully opened the database');
});
module.exports = mongoose;
