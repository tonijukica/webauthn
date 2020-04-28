const express = require('express');
const User = require('../models/user');
const base64url = require('base64url');
const { 
	randomBase64URLBuffer, 
	serverMakeCred, 
	serverGetAssertion, 
	verifyAuthenticatorAttestationResponse, 
	verifyAuthenticatorAssertionResponse 
} = require('../helpers');

const router = express.Router();

router.get('/', (req, res) => {
	res.send('dummy');
});

router.post('/register', async (req, res) => {
	const { email } = req.body;
	if (!email)
		return res.status(400).send('Missing email field');

	const findUser = await User.findOne({ email });

	if (findUser)
		return res.status(400).send('User already exists');
	else {
		const user = await User.create({
			id: randomBase64URLBuffer(8),
			name: email.split('@')[0],
			email,
		});
		user.save();
	
		let makeCredChallenge = serverMakeCred(user.id, user.email);
		makeCredChallenge.status = 'ok';

		req.session.challenge = makeCredChallenge.challenge;
		req.session.email = email;
	
		return res.json(makeCredChallenge);
	}
});

router.post('/registerfail', async(req, res) => {
	const { email } = req.body;
	if (!email)
		return res.status(400).send('Missing email field');

	await User.deleteOne({ email });
	return res.status(200).send('Deleted');
});

router.post('/login', async (req, res) => {
	const { email } = req.body;

	if (!email)
		return res.status(400).send('Missing email field');

	const user = await User.findOne({ email });

	if (!user)
		return res.status(400).send('User does not exist');

	else {
		let getAssertion = serverGetAssertion(user.authenticators);
		getAssertion.status = 'ok';
	
		req.session.challenge = getAssertion.challenge;
		req.session.email = email;
		return res.json(getAssertion);
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
		return res.json({
			status: 'failed',
			message: 'Response missing one or more of id/rawId/response/type fields, or type is not public-key!',
		});
	}
	const { email } = req.session;
	const webAuthnResp = req.body;
	const clientData = JSON.parse(base64url.decode(webAuthnResp.response.clientDataJSON));
	if(clientData.challenge !== req.session.challenge) {
		return res.json({
			'status': 'failed',
			'message': 'Challenges don\'t match!'
		});
	}
	let result;
	let user = await User.findOne({ email });
	if(webAuthnResp.response.attestationObject !== undefined) {
		/* This is create cred */
		result = await verifyAuthenticatorAttestationResponse(webAuthnResp);

		if(result.verified) {
			user.authenticators.push(result.authrInfo);
			user.registered = true;
			user.save();
		}
	} else if(webAuthnResp.response.authenticatorData !== undefined) {
		/* This is get assertion */
		result = await verifyAuthenticatorAssertionResponse(webAuthnResp, user.authenticators);
	} else {
		return res.json({
			'status': 'failed',
			'message': 'Can not determine type of response!'
		});
	}
	if(result.verified) {
		req.session.loggedIn = true;
		return res.json({ 'status': 'ok' });
	} else {
		return res.json({
			'status': 'failed',
			'message': 'Can not authenticate signature!'
		});
	}
});

router.get('/profile', async(req, res) => {
	if(!req.session.loggedIn)
		return res.status(401).send('Denied!');
	
	const user = await User.findOne({ email: req.session.email });

	return res.json(user);
	
});

router.get('/logout', (req, res) => {
	req.session = null;
	return res.send('Logged out');
});

module.exports = router;
