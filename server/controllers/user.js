const { router } = require('express');
const User = require('../models/user');
const { randomBase64Buffer, serverMakeCred, serverGetAssertion } = require('../helpers');

router.post('/register', async(req, res) => {
	const { email } = req.body;
	if(!email)
		res.send(400).send('Missing email field');

	const findUser = await User.findOne({ email });

	if (!findUser) 
		res.status(400).send('User already exists');

	const user = await User.create({
		id: randomBase64Buffer(),
		name: email.split('@')[0],
		email,
	}).save();

	let makeCredChallenge = serverMakeCred(user.id, user.email);
	makeCredChallenge.status = 'ok';
	req.session.challenge = makeCredChallenge.challenge;
	req.session.email = email;

	res.json(makeCredChallenge);
});

router.post('/login', async(req, res) => {
	const { email } = req.body;

	if(!email)
		res.send(400).send('Missing email field');

	const user = await User.findOne({ email });

	if(!user)
		res.send(400).send('User does not exist');

	let getAssertion = serverGetAssertion(user.authenticators);
	getAssertion.status = 'ok';

	req.session.challenge = getAssertion.challenge;
	req.session.email = email;
});

router.post('/response', async(req, res) => {
	
});

module.exports = router;
