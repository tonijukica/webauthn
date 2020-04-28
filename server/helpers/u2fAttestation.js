'use strict';
const base64url = require('base64url');
const { hash, parseAuthData, verifySignature, COSEECDHAtoPKCS } = require('./common');

async function verifyU2FAttestation(ctapCredentialResponse, clientDataJSON) {
	const authenticatorDataStruct = parseAuthData(ctapCredentialResponse.authData);
	if (!(authenticatorDataStruct.flags.up)) 
		throw new Error('User was NOT presented durring authentication!');

	const clientDataHash = hash('SHA256',base64url.decode(clientDataJSON));
	const reservedByte = Buffer.from([0x00]);
	const publicKey = COSEECDHAtoPKCS(authenticatorDataStruct.COSEPublicKey);
	const signatureBase = Buffer.concat([
		reservedByte,
		authenticatorDataStruct.rpIdHash,
		clientDataHash,
		authenticatorDataStruct.credID,
		publicKey,
	]);

	const PEMCertificate = ASN1toPEM(ctapCredentialResponse.attStmt.x5c[0]);
	const signature = ctapCredentialResponse.attStmt.sig;
	const verified = await verifySignature(signature, signatureBase, PEMCertificate);
	return {
		verified, 
		authrInfo: {
			fmt: 'fido-u2f',
			publicKey: base64url(publicKey),
			counter: authenticatorDataStruct.counter,
			credID: base64url(authenticatorDataStruct.credID)
		},
	};
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

module.exports = verifyU2FAttestation;