const encoder = new TextEncoder();

const strToBin = (str) => {
	return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
};

const binToStr = (bin) => {
	return btoa(new Uint8Array(bin).reduce(
		(s, byte) => s + String.fromCharCode(byte), ''
	));
};

export const createCreds = async() => {
	const publicKey = {
		challenge: encoder.encode('Ode ce ic randomBytes(16)'),
		rp: {
			name: 'Toni Webauthn test'
		},
		user: {
			id: encoder.encode('TJ23'),
			name: 'Toni Jukica',
			displayName: 'tjukica'
		}, 
		authenticatorSelection: {
			userVerification: 'preferred'
		}, 
		attestation: 'direct',
		pubKeyCredParams: [
			{
				type: 'public-key',
				alg: -7
			}
		]
	};
	console.log(navigator);
	const res = navigator.credentials.create({
		publicKey
	});
	console.log(res);
	localStorage.setItem('rawId', binToStr(res.rawId));
	localStorage.setItem('id', binToStr(res.id));
};
