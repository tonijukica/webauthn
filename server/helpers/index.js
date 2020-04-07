const crypto = require('crypto');
const base64url = require('base64url');

function randomBase64Buffer() {
	const buffer = crypto.randomBytes(32);
	return base64url(buffer);
}
function randomHex32String() {
	return crypto.randomBytes(32).toString('hex');
}

function serverMakeCred(id, email) {
	const name = email;
	const displayName = email.split('@')[0];

	const makeCredentialds = {
		challenge: randomBase64Buffer(),
		rp: {
			name: 'Toni WebAuthn App',
			id: '',
		},
		user: {
			id,
			name,
			displayName
		},
		attestation: 'direct',
		pubKeyCredParams: [
			{
				type: 'public-key',
				alg: -7
			}
		]
	};

	return makeCredentialds;
}
function serverGetAssertion(authenticators){
	const allowCreds = authenticators.map(authr => {
		return {
			type: 'public-key',
			id: authr.credID,
			transports: ['usb', 'nfc', 'ble', 'internal']
		};
	});
	return {
		challenge: randomBase64Buffer(),
		allowCredentials: allowCreds
	};
}

module.exports = {
	randomBase64Buffer,
	serverMakeCred,
	randomHex32String,
	serverGetAssertion
};
