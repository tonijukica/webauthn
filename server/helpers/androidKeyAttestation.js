'use strict';
const asn1 = require('@lapo/asn1js');
const base64url = require('base64url');
const cbor = require('cbor');
const { hash, parseAuthData, verifySignature, COSEECDHAtoPKCS, base64ToPem, validateCertificationPath } = require('./common');
const { COSE_KEYS } = require('./cose');

async function verifyAndroidKeyAttestation(ctapCredResp, clientDataJSON) {
	const authenticatorDataStruct = parseAuthData(ctapCredResp.authData);
	const clientDataHash = hash('SHA256', clientDataJSON);

	const signatureBase = Buffer.concat([ctapCredResp, clientDataHash]);
	const signature = ctapCredResp.attStmt.sig;

	const leafCert = base64ToPem(ctapCredResp.attStmt.x5c[0].toString('base64'));

	const signatureValid = await verifySignature(signature, signatureBase, leafCert);
	if (!signatureValid) throw new Error('Signature verification failed');

	// let attestationRootCertificateBuffer = attestationStruct.attStmt.x5c[attestationStruct.attStmt.x5c.length - 1];
	// if(attestationRootCertificateBuffer.toString('base64') !== androidkeystoreroot)
	// 	throw new Error('Attestation root is not invalid!');

	const certPath = ctapCredResp.x5c.map((cert) => {
		return base64ToPem(cert.toString('base64'));
	});

	validateCertificationPath(certPath);

	const certASN1 = asn1.decode(ctapCredResp.attStmt.x5c[0]);
	const certJSON = asn1ObjectToJSON(certASN1);
	const certTSB = certJSON.data[0];
	const certPubKey = certTSB.data[6];
	const certPubKeyBuff = certPubKey.data[1].data;

	const coseKey = cbor.decodeAllSync(authenticatorDataStruct.COSEPublicKey)[0];
	const ansiKeyPad = Buffer.concat([Buffer([0x00, 0x04]), coseKey.get(COSE_KEYS.x), coseKey.get(COSE_KEYS.y)]);

	if (ansiKeyPad.toString('hex') !== certPubKeyBuff.toString('hex'))
		throw new Error('Certificate public key does not match public key in authData');

	const attestationExtension = findOID(certASN1, '1.3.6.1.4.1.11129.2.1.17');
	const attestationExtensionJSON = asn1ObjectToJSON(attestationExtension);

	const attestationChallenge = attestationExtensionJSON.data[1].data[0].data[4].data;

	if (attestationChallenge.toString('hex') !== clientDataHashBuf.toString('hex'))
		throw new Error('Certificate attestation challenge is not set to the clientData hash!');

	const softwareEnforcedAuthz = attestationExtensionJSON.data[1].data[0].data[6].data;
	const teeEnforcedAuthz = attestationExtensionJSON.data[1].data[0].data[7].data;

	if (containsASN1Tag(softwareEnforcedAuthz, 600) || containsASN1Tag(teeEnforcedAuthz, 600))
		throw new Error(
			'TEE or Software authorization list contains "allApplication" flag, which means that credential is not bound to the RP!'
		);

	const verifed = true;
	const publicKey = COSEECDHAtoPKCS(authenticatorDataStruct.COSEPublicKey);

	return {
		verifed,
		authrInfo: {
			fmt: 'android-key',
			publicKey: base64url(publicKey),
			counter: authenticatorDataStruct.counter,
			credID: base64url(authenticatorDataStruct.credID),
		},
	};
}

module.exports = verifyAndroidKeyAttestation;

function asn1ObjectToJSON(asn1object) {
	let JASN1 = {
		type: asn1object.typeName(),
	};

	if (!asn1object.sub) {
		if (asn1object.typeName() === 'BIT_STRING' || asn1object.typeName() === 'OCTET_STRING')
			JASN1.data = asn1object.stream.enc.slice(asn1object.posContent(), asn1object.posEnd());
		else JASN1.data = asn1object.content();

		return JASN1;
	}

	JASN1.data = [];
	for (const sub of asn1object.sub) {
		JASN1.data.push(asn1ObjectToJSON(sub));
	}

	return JASN1;
}

function containsASN1Tag(seq, tag) {
	for (const member of seq) if (member.type === '[' + tag + ']') return true;

	return false;
}

function findOID(asn1object, oid) {
	if (!asn1object.sub) return;

	for (let sub of asn1object.sub) {
		if (sub.typeName() !== 'OBJECT_IDENTIFIER' || sub.content() !== oid) {
			let result = findOID(sub, oid);

			if (result) return result;
		} else return asn1object;
	}
}
