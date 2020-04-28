'use strict';
const base64url = require('base64url');
const {
	hash,
	parseAuthData,
	verifySignature,
	COSEECDHAtoPKCS,
	getCertificationInfo,
	gsr2,
	validateCertificationPath,
} = require('./common');

async function verifyAndroidSafetyNeyAttestation(ctapCredResp, clientDataJSON) {
	const authenticatorDataStruct = parseAuthData(ctapCredResp.authData);

	const jwtString = ctapCredResp.attStmt.response.toString('utf8');
	const jwtParts = jwtString.split('.');

	const HEADER = JSON.parse(base64url.decode(jwtParts[0]));
	const PAYLOAD = JSON.parse(base64url.decode(jwtParts[1]));
	const SIGNTURE = jwtParts[2];

	const clientDataHash = hash('SHA256', base64url.toBuffer(clientDataJSON));
	const nonceBase = Buffer.concat([ctapCredResp.authData, clientDataHash]);
	const nonceBuffer = hash('SHA256', nonceBase);
	const expectedNonce = nonceBuffer.toString('base64');

	if (PAYLOAD.nonce !== expectedNonce)
		throw new Error(`PAYLOAD.nonce does not contains expected nonce! Expected ${PAYLOAD.nonce} to equal ${expectedNonce}!`);

	if (!PAYLOAD.ctsProfileMatch) throw new Error('PAYLOAD.ctsProfileMatch is FALSE!');

	const certPath = HEADER.x5c.concat([gsr2]).map((cert) => {
		let pemcert = '';
		for (let i = 0; i < cert.length; i += 64) pemcert += cert.slice(i, i + 64) + '\n';
		return '-----BEGIN CERTIFICATE-----\n' + pemcert + '-----END CERTIFICATE-----';
	});

	const { subject } = getCertificationInfo(certPath[0]);
	if (subject.CN !== 'attest.android.com') throw new Error('The common name is not set to "attest.android.com"!');

	validateCertificationPath(certPath);

	const signatureBaseBuffer = Buffer.from(jwtParts[0] + '.' + jwtParts[1]);
	const certificate = certPath[0];
	const signatureBuffer = base64url.toBuffer(SIGNTURE);

	const validSignature = await verifySignature(signatureBuffer, signatureBaseBuffer, certificate);

	if (!validSignature) throw new Error('Failed to verify the signature!');

	const publicKey = COSEECDHAtoPKCS(authenticatorDataStruct.COSEPublicKey);

	return {
		verified: validSignature,
		authrInfo: {
			fmt: 'android-safetynet',
			publicKey: base64url(publicKey),
			counter: authenticatorDataStruct.counter,
			credID: base64url(authenticatorDataStruct.credID),
		},
	};
}

module.exports = verifyAndroidSafetyNeyAttestation;
