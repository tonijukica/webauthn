'use strict';
const crypto = require('crypto');
const cbor = require('cbor');

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

	const credIDLen  = credIDLenBuf.readUInt16BE(0);
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

module.exports = {
	hash,
	parseAuthData,
	verifySignature,
	COSEECDHAtoPKCS
};