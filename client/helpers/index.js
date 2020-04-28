import base64url from './base64url-arraybuffer';

function publicKeyCredentialToJSON(pubKeyCred) {
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
	makeCredReq.challenge = base64url.decode(makeCredReq.challenge);
	makeCredReq.user.id = base64url.decode(makeCredReq.user.id);

	return makeCredReq;
};

let preformatGetAssertReq = (getAssert) => {
	getAssert.challenge = base64url.decode(getAssert.challenge);
    
	for(let allowCred of getAssert.allowCredentials) {
		allowCred.id = base64url.decode(allowCred.id);
	}

	return getAssert;
};

export { publicKeyCredentialToJSON, generateRandomBuffer, preformatGetAssertReq, preformatMakeCredReq };
