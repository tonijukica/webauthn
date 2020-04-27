'use strict';

const COSE_KEYS = {
	'kty' : 1,
	'alg' : 3,
	'crv' : -1,
	'x'   : -2,
	'y'   : -3,
	'n'   : -1,
	'e'   : -2
};
const COSE_KTY = {
	'OKP': 1,
	'EC2': 2,
	'RSA': 3
};

const COSE_RSA_SCHEME = {
	'-3': 'pss-sha256',
	'-39': 'pss-sha512',
	'-38': 'pss-sha384',
	'-65535': 'pkcs1-sha1',
	'-257': 'pkcs1-sha256',
	'-258': 'pkcs1-sha384',
	'-259': 'pkcs1-sha512'
};

const COSE_CRV = {
	'1': 'p256',
	'2': 'p384',
	'3': 'p521'
};

const COSE_ALG_HASH = {
	'-257': 'sha256',
	'-258': 'sha384',
	'-259': 'sha512',
	'-65535': 'sha1',
	'-39': 'sha512',
	'-38': 'sha384',
	'-37': 'sha256',
	'-260': 'sha256',
	'-261': 'sha512',
	'-7': 'sha256',
	'-36': 'sha384',
	'-37': 'sha512'
};

module.exports = { 
	COSE_KEYS,
	COSE_KTY,
	COSE_RSA_SCHEME,
	COSE_CRV,
	COSE_ALG_HASH
};