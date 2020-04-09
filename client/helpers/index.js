import * as base64url from 'base64url';

function publicKeyCredentialToJSON(pubKeyCred) {
	console.log(pubKeyCred);
	if (pubKeyCred instanceof Array) {
		let arr = [];
		for (let i of pubKeyCred) arr.push(publicKeyCredentialToJSON(i));

		return arr;
	}

	else if (pubKeyCred instanceof ArrayBuffer) {
		return base64url.encode(pubKeyCred);
	}

	else if (pubKeyCred instanceof Object) {
		let obj = {};

		for (let key in pubKeyCred) {
			obj[key] = publicKeyCredentialToJSON(pubKeyCred[key]);
		}

		return obj;
	}

	return pubKeyCred;
}

function generateRandomBuffer(len) {
	len = len || 32;

	const randomBuffer = new Uint8Array(len);
	window.crypto.getRandomValues(randomBuffer);

	return randomBuffer;
}

let  preformatMakeCredReq = (makeCredReq) => {
	console.log(makeCredReq.challenge);
	const challenge = base64url.decode(makeCredReq.challenge);
	const id = base64url.decode(makeCredReq.user.id);

	return {
		challenge: Buffer.from(challenge, 'utf8'),
		rp: {
			name: 'Toni WebAuthn App'
		},
		user: {
			id: Buffer.from(id, 'utf8'),
			name: makeCredReq.user.name,
			displayName: makeCredReq.user.displayName
		},
		attestation: 'direct',
		pubKeyCredParams: [
			{
				type: 'public-key',
				alg: -7
			}
		]
	};
};

function preformatGetAssertReq(getAssert) {
	console.log(getAssert);
	console.log(base64url.decode(getAssert.status));
	const challenge = base64url.decode(getAssert.challenge);
	getAssert.challenge = Buffer.from(challenge, 'utf8');

	for (let allowCred of getAssert.allowCredentials) {
		const id =  base64url.decode(allowCred.id);
		allowCred.id = Buffer.from(id, 'utf-8');
	}

	return getAssert;
}
export { publicKeyCredentialToJSON, generateRandomBuffer, preformatGetAssertReq, preformatMakeCredReq };
