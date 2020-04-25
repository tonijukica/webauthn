const crypto = require('crypto');
const base64url = require('base64url');
const cbor = require('cbor');
const util = require('util');
const decodeAll = util.promisify(cbor.decodeAll);

const U2F_USER_PRESENTED = 0x01;
let gsr2 = 'MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8omUVCxKs+IVSbC9N/hHD6ErPLv4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7SqbKSaZeqKeMWhG8eoLrvozps6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQBoZfXklqtTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzdC9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pazq+r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCBmTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUm+IHV2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4GsJ0/WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavSot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG79G+dwfCMNYxdAfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7TBj0/VLZjmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg==';
function verifySignature (signature, data, publicKey){
	return crypto.createVerify('SHA256')
		.update(data)
		.verify(publicKey, signature);
}

function randomBase64Buffer() {
	const buffer = crypto.randomBytes(32);
	return base64url.encode(buffer.toString('utf8'));
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
	console.log(allowCreds);
	return {
		challenge: randomBase64Buffer(),
		allowCredentials: allowCreds
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
	const base64Certificate = pkBuffer.toString('hex');
	let PEMKey = '';

	for(let i = 0; i < Math.ceil(base64Certificate.length/64); i++){
		const start = 64 * i;
		PEMKey += base64Certificate.substr(start,64) +'\n';
	}

	PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`;

	return PEMKey;
}

function getCertificateSubject (certificate){
	let subjectCert = new jsrsasign.X509();
	subjectCert.readCertPEM(certificate);

	let subjectString = subjectCert.getSubjectString();
	let subjectFields = subjectString.slice(1).split('/');

	let fields = {};
	for(let field of subjectFields) {
		let kv = field.split('=');
		fields[kv[0]] = kv[1];
	}
	return fields;
}


var validateCertificatePath = (certificates) => {
	if((new Set(certificates)).size !== certificates.length)
		throw new Error('Failed to validate certificates path! Dublicate certificates detected!');

	for(let i = 0; i < certificates.length; i++) {
		let subjectPem  = certificates[i];
		let subjectCert = new jsrsasign.X509();
		subjectCert.readCertPEM(subjectPem);

		let issuerPem = '';
		if(i + 1 >= certificates.length)
			issuerPem = subjectPem;
		else
			issuerPem = certificates[i + 1];

		let issuerCert = new jsrsasign.X509();
		issuerCert.readCertPEM(issuerPem);

		if(subjectCert.getIssuerString() !== issuerCert.getSubjectString())
			throw new Error('Failed to validate certificate path! Issuers dont match!');

		let subjectCertStruct = jsrsasign.ASN1HEX.getTLVbyList(subjectCert.hex, 0, [0]);
		let algorithm         = subjectCert.getSignatureAlgorithmField();
		let signatureHex      = subjectCert.getSignatureValueHex();

		let Signature = new jsrsasign.crypto.Signature({alg: algorithm});
		Signature.init(issuerPem);
		Signature.updateHex(subjectCertStruct);

		if(!Signature.verify(signatureHex))
			throw new Error('Failed to validate certificate path!');
	}

	return true;
};

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
		console.log(authrDataStruct);
		if(!(authrDataStruct.flags & U2F_USER_PRESENTED))
			throw new Error('User was NOT presented durring authentication!');

		const clientDataHash  = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON));
		const reservedByte    = Buffer.from([0x00]);
		const publicKey       = await COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey);
		const signatureBase   = Buffer.concat([reservedByte, authrDataStruct.rpIdHash, clientDataHash, authrDataStruct.credID, publicKey]);

		const PEMCertificate = ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0]);
		const signature      = ctapMakeCredResp.attStmt.sig;

		response.verified = verifySignature(signature, signatureBase, PEMCertificate);

		if(response.verified) {
			response.authrInfo = {
				fmt: 'fido-u2f',
				publicKey: base64url.encode(publicKey),
				counter: authrDataStruct.counter,
				credID: base64url.encode(authrDataStruct.credID)
			};
		}
	}
	else if(ctapMakeCredResp.fmt === 'android-safetynet'){
		let jwsString = ctapMakeCredResp.attStmt.response.toString('utf8');
		let jwsParts = jwsString.split('.');

		let HEADER    = JSON.parse(base64url.decode(jwsParts[0]));
		let PAYLOAD   = JSON.parse(base64url.decode(jwsParts[1]));
		let SIGNATURE = jwsParts[2];

		console.log(HEADER, PAYLOAD, SIGNATURE);

		const clientDataHash  = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON));
		const nonceBase = Buffer.concat([ctapMakeCredResp.authData, clientDataHash]);
		const nonceBuffer = hash(nonceBase);
		const expectedNonce = nonceBuffer.toString('base64');

		if(PAYLOAD.nonce !== expectedNonce)
			throw new Error(`PAYLOAD.nonce does not contains expected nonce! Expected ${PAYLOAD.nonce} to equal ${expectedNonce}!`);

		if(!PAYLOAD.ctsProfileMatch)
			throw new Error('PAYLOAD.ctsProfileMatch is FALSE!');

		let certPath = HEADER.x5c.concat([gsr2]).map((cert) => {
			let pemcert = '';
			for(let i = 0; i < cert.length; i += 64)
				pemcert += cert.slice(i, i + 64) + '\n';

			return '-----BEGIN CERTIFICATE-----\n' + pemcert + '-----END CERTIFICATE-----';
		});

		if(getCertificateSubject(certPath[0]).CN !== 'attest.android.com')
			throw new Error('The common name is not set to "attest.android.com"!');
		
		validateCertificatePath(certPath);	

		let signatureBaseBuffer = Buffer.from(jwsParts[0] + '.' + jwsParts[1]);
		let certificate         = certPath[0];
		let signatureBuffer     = base64url.toBuffer(SIGNATURE);

		let signatureIsValid    = crypto.createVerify('sha256')
			.update(signatureBaseBuffer)
			.verify(certificate, signatureBuffer);

		if(!signatureIsValid)
			throw new Error('Failed to verify the signature!');

		result.verified = true;
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
	randomBase64Buffer,
	serverMakeCred,
	randomHex32String,
	serverGetAssertion,
	verifyAuthenticatorAssertionResponse,
	verifyAuthenticatorAttestationResponse
};
