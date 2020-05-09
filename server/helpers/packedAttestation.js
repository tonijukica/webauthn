'use strict';
const base64url = require('base64url');
const elliptic = require('elliptic');
const nodeRSA = require('node-rsa');
const cbor = require('cbor');
const { hash, parseAuthData, verifySignature, COSEECDHAtoPKCS, base64ToPem, getCertificationInfo } = require('./common');
const { COSE_ALG_HASH, COSE_KEYS, COSE_KTY, COSE_CRV, COSE_RSA_SCHEME } = require('./cose');

async function verifyPackedAttestation(ctapCredentialResponse, clientDataJSON){
	const authenticatorDataStruct = parseAuthData(ctapCredentialResponse.authData);
	const clientDataHash = hash('SHA256',base64url.decode(clientDataJSON));
	const signatureBase = Buffer.concat([
		ctapCredentialResponse.authData,
		clientDataHash
	]);

	const signature = ctapCredentialResponse.attStmt.sig;

	if(ctapCredentialResponse.attStmt.x5c){
		const leafCert = base64ToPem(ctapCredentialResponse.attStmt.x5c[0].toString('base64'));
		const certInfo = getCertificationInfo(leafCert);

		if(certInfo.subject.OU !== 'Authenticator Attestation')
			throw new Error('Batch certificate OU MUST be set strictly to "Authenticator Attestation"!');

		if(!certInfo.subject.CN)
			throw new Error('Batch certificate CN MUST no be empty!');

		if(!certInfo.subject.O)
			throw new Error('Batch certificate CN MUST no be empty!');

		if(!certInfo.subject.C || certInfo.subject.C.length !== 2)
			throw new Error('Batch certificate C MUST be set to two character ISO 3166 code!');

		if(certInfo.basicConstraintsCA)
			throw new Error('Batch certificate basic constraints CA MUST be false!');

		if(certInfo.version !== 3)
			throw new Error('Batch certificate version MUST be 3(ASN1 2)!');
		
		const verified = await verifySignature(signature, signatureBase, leafCert);
		const publicKey = COSEECDHAtoPKCS(authenticatorDataStruct.COSEPublicKey);

		return {
			verified,
			authrInfo: {
				fmt: 'packed',
				publicKey:  base64url(publicKey),
				counter: authenticatorDataStruct.counter,
				credID: base64url(authenticatorDataStruct.credID)
			}
		};
	}
	else if(ctapCredentialResponse.attStmt.ecdaaKeyId)
		throw new Error('ECDAA not implemented yet');
	
	else{
		const publicKeyCose = cbor.decodeAllSync(authenticatorDataStruct.COSEPublicKey)[0];
		const hashAlg = COSE_ALG_HASH[publicKeyCose.get(COSE_KEYS.alg)];
		if(publicKeyCose.get(COSE_KEYS.kty) === COSE_KTY.EC2){
			const ansiKey = COSEECDHAtoPKCS(publicKeyCose);

			const signatureBaseHash = hash(hashAlg, signatureBase);

			const ec = new elliptic.ec(COSE_CRV[publicKeyCose.get(COSE_KEYS.crv)]);
			const key = ec.keyFromPublic(ansiKey);

			const verifed = key.verify(signatureBaseHash, signature);
			
			return {
				verifed, 
				authrInfo: {
					fmt: 'packed',
					publicKey: ansiKey,
					counter: authenticatorDataStruct.counter,
					credID: base64url(authenticatorDataStruct.credID)
				}
			};
		}
		else if(publicKeyCose.get(COSE_KEYS.kty) === COSE_KTY.RSA){
			const signingScheme = COSE_RSA_SCHEME[publicKeyCose.get(COSE_KEYS.alg)];
			const key = new nodeRSA(undefined, { signingScheme });
			key.importKey({
				n: publicKeyCose.get(COSE_KEYS.n),
				e: publicKeyCose.get(COSE_KEYS.e)
			}, 'components-public');
			const verified = key.verify(signatureBase, signature);
			return {
				verified, 
				authrInfo: {
					fmt: 'packed',
					publicKey: key.exportKey('pkcs1-public-pem'),
					counter: authenticatorDataStruct.counter,
					credID: base64url(authenticatorDataStruct.credID)
				}
			};
		}
		else if(publicKeyCose.get(COSE_KEYS.kty) === COSE_KTY.OKP){
			//Probly won't work
			const x = publicKeyCose.get(COSE_KEYS.x);
			const signatureBaseHash = hash(hashAlg, signatureBase);

			const key = new elliptic.eddsa('ed25519');
			key.keyFromPublic(x);

			const verifed = key.verify(signatureBaseHash, signature);
			return {
				verifed, 
				authrInfo: {
					fmt: 'packed',
					publicKey: key,
					counter: authenticatorDataStruct.counter,
					credID: base64url(authenticatorDataStruct.credID)
				}
			};
		}
	}
}

module.exports = verifyPackedAttestation;


