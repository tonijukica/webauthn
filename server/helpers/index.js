'use strict';
const crypto = require('crypto');
const base64url = require('base64url');
const cbor = require('cbor');
const verifyU2FAttestation = require('./u2fAttestation');
const verifyPackedAttestation = require('./packedAttestation');
const verifyAndroidKeyAttestation = require('./androidKeyAttestation');
const verifyAndroidSafetyNetAttestation = require('./androidSafetyNetAttestation');
const noneAttestation = require('./noneAttestation');

async function verifySignature(signature, data, publicKey) {
	return await crypto.createVerify('SHA256').update(data).verify(publicKey, signature);
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
			displayName,
		},
		attestation: 'direct',
		pubKeyCredParams: [
			{
				type: 'public-key',
				alg: -7,
			},
			{
				type: 'public-key',
				alg: -35,
			},
			{
				type: 'public-key',
				alg: -36,
			},
			{
				type: 'public-key',
				alg: -257,
			},
			{
				type: 'public-key',
				alg: -258,
			},
			{
				type: 'public-key',
				alg: -259,
			},
			{
				type: 'public-key',
				alg: -38,
			},
			{
				type: 'public-key',
				alg: -39,
			},
			{
				type: 'public-key',
				alg: -8,
			},
		],
		authenticatorSelection: {
			requireResidentKey: false,
			userVerification: 'discouraged'
		}
	};

	return makeCredentialds;
}
function serverGetAssertion(authenticators) {
	const rpId = process.env.RP_ID || 'localhost';
	const allowCreds = authenticators.map((authr) => {
		return {
			type: 'public-key',
			id: authr.credID,
			transports: ['usb', 'nfc', 'ble', 'internal'],
		};
	});
	return {
		challenge: randomBase64URLBuffer(32),
		allowCredentials: allowCreds,
		userVerification: 'discouraged',
		rpId,
		extensions: {
			txAuthSimple: '',
		},
		timeout: 60000,
	};
}
function hash(data) {
	return crypto.createHash('SHA256').update(data).digest();
}

function ASN1toPEM(pkBuffer) {
	if (!Buffer.isBuffer(pkBuffer)) throw new Error('ASN1toPEM: input must be a Buffer');
	let type;
	if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
		pkBuffer = Buffer.concat([new Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'), pkBuffer]);
		type = 'PUBLIC KEY';
	} else type = 'CERTIFICATE';
	const base64Certificate = pkBuffer.toString('base64');
	let PEMKey = '';

	for (let i = 0; i < Math.ceil(base64Certificate.length / 64); i++) {
		const start = 64 * i;
		PEMKey += base64Certificate.substr(start, 64) + '\n';
	}

	PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`;

	return PEMKey;
}

async function verifyAuthenticatorAttestationResponse(webAuthnResponse) {
	const attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject);
	const ctapMakeCredResp = cbor.decodeAllSync(attestationBuffer)[0];
	const { clientDataJSON } = webAuthnResponse.response;
	let verification;
	console.log(ctapMakeCredResp);
	if (ctapMakeCredResp.fmt === 'fido-u2f') 
		verification = await verifyU2FAttestation(ctapMakeCredResp, clientDataJSON);
	else if (ctapMakeCredResp.fmt === 'packed')
		verification = await verifyPackedAttestation(ctapMakeCredResp, clientDataJSON);
	else if (ctapMakeCredResp.fmt === 'android-key')
		verification = await verifyAndroidKeyAttestation(ctapMakeCredResp, clientDataJSON);
	else if (ctapMakeCredResp.fmt === 'android-safetynet')
		verification = await verifyAndroidSafetyNetAttestation(ctapMakeCredResp, clientDataJSON);
	else if (ctapMakeCredResp.fmt === 'none')
		verification = await noneAttestation(ctapMakeCredResp, clientDataJSON);

	const { verified, authrInfo } = verification;
	if (verified) {
		const response = {
			verified,
			authrInfo,
		};
		return response;
	}
	else 
		return {
			verified: false,
		};
}

function findAuthenticator(credID, authenticators) {
	for (const authr of authenticators) {
		if (authr.credID === credID) return authr;
	}
	throw new Error(`Unknown authenticator with credID ${credID}!`);
}

function parseGetAssertAuthData(buffer) {
	const rpIdHash = buffer.slice(0, 32);
	buffer = buffer.slice(32);

	const flagsBuf = buffer.slice(0, 1);
	buffer = buffer.slice(1);

	const flagsInt = flagsBuf[0];
	const flags = {
		up: !!(flagsInt & 0x01),
		uv: !!(flagsInt & 0x04),
		at: !!(flagsInt & 0x40),
		ed: !!(flagsInt & 0x80),
		flagsInt,
	};

	const counterBuf = buffer.slice(0, 4);
	buffer = buffer.slice(4);

	const counter = counterBuf.readUInt32BE(0);

	return { rpIdHash, flagsBuf, flags, counter, counterBuf };
}

async function verifyAuthenticatorAssertionResponse(webAuthnResponse, authenticators) {
	const authr = findAuthenticator(webAuthnResponse.id, authenticators);
	const authenticatorData = base64url.toBuffer(webAuthnResponse.response.authenticatorData);

	let response = { verified: false };
	if (authr.fmt === 'fido-u2f' || authr.fmt === 'packed' || authr.fmt === 'android-safetynet' || authr.fmt === 'android-key' || authr.fmt === 'none') {
		let authrDataStruct = parseGetAssertAuthData(authenticatorData);

		if (!authrDataStruct.flags.up) throw new Error('User was NOT presented durring authentication!');

		const clientDataHash = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON));
		const signatureBase = Buffer.concat([
			authrDataStruct.rpIdHash,
			authrDataStruct.flagsBuf,
			authrDataStruct.counterBuf,
			clientDataHash,
		]);
		const publicKey = checkPEM(authr.publicKey) ? 
			authr.publicKey.toString('base64')
			:
			ASN1toPEM(base64url.toBuffer(authr.publicKey))
		;
		const signature = base64url.toBuffer(webAuthnResponse.response.signature);
		response.verified = await verifySignature(signature, signatureBase, publicKey);

		if (response.verified) {
			if (response.counter <= authr.counter) throw new Error('Authr counter did not increase!');

			authr.counter = authrDataStruct.counter;
		}
	}

	return response;
}
function checkPEM(pubKey){
	return pubKey.toString('base64').includes('BEGIN');
}

module.exports = {
	randomBase64URLBuffer,
	serverMakeCred,
	randomHex32String,
	serverGetAssertion,
	verifyAuthenticatorAssertionResponse,
	verifyAuthenticatorAttestationResponse,
};
