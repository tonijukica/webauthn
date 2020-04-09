const express = require('express');
const User = require('../models/user');
const base64url = require('base64url');
const { randomBase64Buffer, serverMakeCred, serverGetAssertion } = require('../helpers');

const router = express.Router();
router.get('/', (req, res) => {
	res.send('dummy');
});

router.post('/register', async (req, res) => {
	const { email } = req.body;
	if (!email)
		res.send(400).send('Missing email field');

	const findUser = await User.findOne({ email });

	if (findUser)
		res.status(400).send('User already exists');
	else {
		const user = await User.create({
			id: randomBase64Buffer(),
			name: email.split('@')[0],
			email,
		});
		user.save();
		console.log(user);
	
		let makeCredChallenge = serverMakeCred(user.id, user.email);
		makeCredChallenge.status = 'ok';
		console.log(makeCredChallenge);

		req.session.challenge = makeCredChallenge.challenge;
		req.session.email = email;
	
		res.json(makeCredChallenge);
	}
	
});

router.post('/login', async (req, res) => {
	const { email } = req.body;

	if (!email)
		res.status(400).send('Missing email field');

	const user = await User.findOne({ email });

	if (!user)
		res.status(400).send('User does not exist');

	else {
		console.log(user);
		let getAssertion = serverGetAssertion(user.authenticators);
		getAssertion.status = 'ok';
		console.log(getAssertion);
	
		req.session.challenge = getAssertion.challenge;
		req.session.email = email;
		req.session.test = 'test';
		req.session.tes2 = null;
		res.json(getAssertion);
	}
});

router.post('/response', async (req, res) => {
	if (
		!req.body ||
		!req.body.id ||
		!req.body.rawId ||
		!req.body.response ||
		!req.body.type ||
		req.body.type !== 'public-key'
	){
		res.json({
			status: 'failed',
			message: 'Response missing one or more of id/rawId/response/type fields, or type is not public-key!',
		});
		return;
	}
	const { email } = req.session;
	const webAuthnResp = req.body;
	const clientData = JSON.parse(base64url.decode(webAuthnResp.response.clientDataJSON));
	if(clientData.challenge !== req.session.challenge) {
		res.json({
			'status': 'failed',
			'message': 'Challenges don\'t match!'
		});
	}
	let result;
	let user = await User.findOne({ email });
	if(webauthnResp.response.attestationObject !== undefined) {
		/* This is create cred */
		result = utils.verifyAuthenticatorAttestationResponse(webauthnResp);

		if(result.verified) {
			user.authenticators.push(result.authrInfo);
			user.registered = true;
			user.save();
		}
	} else if(webauthnResp.response.authenticatorData !== undefined) {
		/* This is get assertion */
		result = utils.verifyAuthenticatorAssertionResponse(webauthnResp, user.authenticators);
	} else {
		res.json({
			'status': 'failed',
			'message': 'Can not determine type of response!'
		});
	}

	if(result.verified) {
		res.session.loggedIn = true;
		res.json({ 'status': 'ok' });
	} else {
		res.json({
			'status': 'failed',
			'message': 'Can not authenticate signature!'
		});
	}
});

module.exports = router;
