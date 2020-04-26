const crypto = require('crypto');
const base64url = require('base64url');
const cbor = require('cbor');

const U2F_USER_PRESENTED = 0x01;
async function verifySignature (signature, data, publicKey){
	return await crypto.createVerify('SHA256')
		.update(data)
		.verify(publicKey, signature);
}
let randomBase64URLBuffer = (len) => {
	len = len || 32;

	let buff = crypto.randomBytes(len);

	return base64url(buff);
};

function randomHex32String() {
	return crypto.randomBytes(32).toString('hex');
}

function serverMakeCred(id, email) {
	const name = email;
	const displayName = email.split('@')[0];

	const makeCredentialds = {
		challenge: randomBase64URLBuffer(32),
		rp: {
			name: 'Toni WebAuthn App',
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
		challenge: randomBase64URLBuffer(32),
		allowCredentials: allowCreds,
		userVerification: 'discouraged',
		rpId: 'localhost',
		extensions: {
			txAuthSimple: ''
		},
		timeout: 60000, 
	};
}
function hash(data){
	return crypto.createHash('SHA256').update(data).digest();
}

async function COSEECDHAtoPKCS (COSEPublicKey) {
	// check promisifed fn
	const coseStruct = cbor.decodeAllSync(COSEPublicKey)[0];
	const tag = Buffer.from([0x04]);
	const x = coseStruct.get(-2);
	const y = coseStruct.get(-3);

	return Buffer.concat([tag, x, y]);
}

function ASN1toPEM(pkBuffer) {
	if(!Buffer.isBuffer(pkBuffer))
		throw new Error('ASN1toPEM: input must be a Buffer');
	let type;
	if(pkBuffer.length == 65 && pkBuffer[0] == 0x04){
		pkBuffer = Buffer.concat([
			new Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'),
			pkBuffer
		]);
		type = 'PUBLIC KEY';
	}
	else
		type = 'CERTIFICATE';
	const base64Certificate = pkBuffer.toString('base64');
	let PEMKey = '';

	for(let i = 0; i < Math.ceil(base64Certificate.length/64); i++){
		const start = 64 * i;
		PEMKey += base64Certificate.substr(start,64) +'\n';
	}

	PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`;

	return PEMKey;
}


function parseMakeCredAuthData (buffer){
	const rpIdHash      = buffer.slice(0, 32);          buffer = buffer.slice(32);
	const flagsBuf      = buffer.slice(0, 1);           buffer = buffer.slice(1);
	const flags         = flagsBuf[0];
	const counterBuf    = buffer.slice(0, 4);           buffer = buffer.slice(4);
	const counter       = counterBuf.readUInt32BE(0);
	const aaguid        = buffer.slice(0, 16);          buffer = buffer.slice(16);
	const credIDLenBuf  = buffer.slice(0, 2);           buffer = buffer.slice(2);
	const credIDLen     = credIDLenBuf.readUInt16BE(0);
	const credID        = buffer.slice(0, credIDLen);   buffer = buffer.slice(credIDLen);
	const COSEPublicKey = buffer;

	return {rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey};
}

async function verifyAuthenticatorAttestationResponse (webAuthnResponse){
	const attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject);
	const ctapMakeCredResp = cbor.decodeAllSync(attestationBuffer)[0];
	console.log(ctapMakeCredResp);

	let response = {
		'verified': false
	};

	if(ctapMakeCredResp.fmt === 'fido-u2f') {
		const authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData);
		
		if(!(authrDataStruct.flags & U2F_USER_PRESENTED))
			throw new Error('User was NOT presented durring authentication!');

		const clientDataHash  = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON));
		const reservedByte    = Buffer.from([0x00]);
		const publicKey       = await COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey);
		const signatureBase   = Buffer.concat([reservedByte, authrDataStruct.rpIdHash, clientDataHash, authrDataStruct.credID, publicKey]);

		const PEMCertificate = ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0]);
		console.log(PEMCertificate);
		const signature      = ctapMakeCredResp.attStmt.sig;

		response.verified = await verifySignature(signature, signatureBase, PEMCertificate);
		console.log(response.verified + 'yikes');

		if(response.verified) {
			console.log('in???');
			response.authrInfo = {
				fmt: 'fido-u2f',
				publicKey: base64url.encode(publicKey),
				counter: authrDataStruct.counter,
				credID: base64url.encode(authrDataStruct.credID)
			};
			return response;
		}
	}
	return response;
}

function findAuthenticator (credID, authenticators) {
	for(const authr of authenticators) {
		if(authr.credID === credID)
			return authr;
	}
	throw new Error(`Unknown authenticator with credID ${credID}!`);
}

function parseGetAssertAuthData (buffer) {
	const rpIdHash      = buffer.slice(0, 32);          buffer = buffer.slice(32);
	const flagsBuf      = buffer.slice(0, 1);           buffer = buffer.slice(1);
	const flags         = flagsBuf[0];
	const counterBuf    = buffer.slice(0, 4);           buffer = buffer.slice(4);
	const counter       = counterBuf.readUInt32BE(0);

	return {rpIdHash, flagsBuf, flags, counter, counterBuf};
}

function verifyAuthenticatorAssertionResponse (webAuthnResponse, authenticators){
	const authr = findAuthenticator(webAuthnResponse.id, authenticators);
	const authenticatorData = base64url.toBuffer(webAuthnResponse.response.authenticatorData);

	let response = {'verified': false};
	if(authr.fmt === 'fido-u2f') {
		let authrDataStruct  = parseGetAssertAuthData(authenticatorData);

		if(!(authrDataStruct.flags & U2F_USER_PRESENTED))
			throw new Error('User was NOT presented durring authentication!');

		const clientDataHash   = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON));
		const signatureBase    = Buffer.concat([authrDataStruct.rpIdHash, authrDataStruct.flagsBuf, authrDataStruct.counterBuf, clientDataHash]);

		const publicKey = ASN1toPEM(base64url.toBuffer(authr.publicKey));
		const signature = base64url.toBuffer(webAuthnResponse.response.signature);

		response.verified = verifySignature(signature, signatureBase, publicKey);

		if(response.verified) {
			if(response.counter <= authr.counter)
				throw new Error('Authr counter did not increase!');

			authr.counter = authrDataStruct.counter;
		}
	}

	return response;
};


module.exports = {
	randomBase64URLBuffer,
	serverMakeCred,
	randomHex32String,
	serverGetAssertion,
	verifyAuthenticatorAssertionResponse,
	verifyAuthenticatorAttestationResponse
};
