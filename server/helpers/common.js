'use strict';
const crypto = require('crypto');
const cbor = require('cbor');
const jsrsasign = require('jsrsasign');

function hash(alg, data) {
	return crypto.createHash(alg).update(data).digest();
}

function parseAuthData(buffer) {
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
		flagsInt
	};

	const counterBuf = buffer.slice(0, 4);
	buffer = buffer.slice(4);

	const counter = counterBuf.readUInt32BE(0);
	const aaguid = buffer.slice(0, 16);
	buffer = buffer.slice(16);

	const credIDLenBuf = buffer.slice(0, 2);
	buffer = buffer.slice(2);

	const credIDLen = credIDLenBuf.readUInt16BE(0);
	const credID = buffer.slice(0, credIDLen);
	buffer = buffer.slice(credIDLen);

	const COSEPublicKey = buffer;

	return {
		rpIdHash,
		flagsBuf,
		flags,
		counter,
		counterBuf,
		aaguid,
		credID,
		COSEPublicKey
	};
}
async function verifySignature(signature, data, publicKey) {
	return await crypto.createVerify('SHA256').update(data).verify(publicKey, signature);
}

function COSEECDHAtoPKCS(COSEPublicKey) {
	const coseStruct = cbor.decodeAllSync(COSEPublicKey)[0];
	const tag = Buffer.from([0x04]);
	const x = coseStruct.get(-2);
	const y = coseStruct.get(-3);

	return Buffer.concat([tag, x, y]);
}

function base64ToPem(base64cert) {
	let pemcert = '';
	for (let i = 0; i < base64cert.length; i += 64) 
		pemcert += base64cert.slice(i, i + 64) + '\n';

	return '-----BEGIN CERTIFICATE-----\n' + pemcert + '-----END CERTIFICATE-----';
}

function validateCertificationPath(certificates) {
	if (new Set(certificates).size !== certificates.length)
		throw new Error('Failed to validate certificates path! Dublicate certificates detected!');

	for (let i = 0; i < certificates.length; i++) {
		const subjectPem = certificates[i];
		const subjectCert = new jsrsasign.X509();
		subjectCert.readCertPEM(subjectPem);

		let issuerPem = '';
		if (i + 1 >= certificates.length) issuerPem = subjectPem;
		else issuerPem = certificates[i + 1];

		const issuerCert = new jsrsasign.X509();
		issuerCert.readCertPEM(issuerPem);

		if (subjectCert.getIssuerString() !== issuerCert.getSubjectString())
			throw new Error('Failed to validate certificate path! Issuers dont match!');

		const subjectCertStruct = jsrsasign.ASN1HEX.getTLVbyList(subjectCert.hex, 0, [0]);
		const algorithm = subjectCert.getSignatureAlgorithmField();
		const signatureHex = subjectCert.getSignatureValueHex();

		const Signature = new jsrsasign.crypto.Signature({ alg: algorithm });
		Signature.init(issuerPem);
		Signature.updateHex(subjectCertStruct);

		if (!Signature.verify(signatureHex)) throw new Error('Failed to validate certificate path!');
	}
}

function getCertificationInfo(certificate) {
	let subjectCert = new jsrsasign.X509();
	subjectCert.readCertPEM(certificate);

	const subjectString = subjectCert.getSubjectString();
	const subjectParts = subjectString.slice(1).split('/');

	let subject = {};
	for (const field of subjectParts) {
		const kv = field.split('=');
		subject[kv[0]] = kv[1];
	}

	const version = subjectCert.version;
 	const basicConstraintsCA = !!subjectCert.getExtBasicConstraints().cA;
	
	return {
		subject,
		version,
		basicConstraintsCA,
	};
}

const gsr2 =
	'MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8omUVCxKs+IVSbC9N/hHD6ErPLv4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7SqbKSaZeqKeMWhG8eoLrvozps6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQBoZfXklqtTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzdC9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pazq+r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCBmTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUm+IHV2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4GsJ0/WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavSot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG79G+dwfCMNYxdAfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7TBj0/VLZjmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg==';

module.exports = {
	hash,
	parseAuthData,
	verifySignature,
	COSEECDHAtoPKCS,
	base64ToPem,
	validateCertificationPath,
	getCertificationInfo,
	gsr2
};
