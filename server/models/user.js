const mongoose = require('mongoose');

const User = mongoose.model(
	new mongoose.Schema({
		id: {
			type: String
		},
		name: {
			type: String,
		},
		email: {
			type: String,
		},
		authenticators: {
			type: Array
		},
		registered: {
			type: Boolean,
			default: false
		}
	})
);

module.exports = User;
