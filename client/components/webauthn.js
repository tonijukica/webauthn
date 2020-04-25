function getMakeCredentialsChallenge(formBody){
	return fetch('http://localhost:8080/webauthn/register', {
		method: 'POST',
		credentials: 'include',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify(formBody),
	})
		.then((response) => response.json())
		.then((response) => {
			if (response.status !== 'ok') 
				throw new Error(`Server responed with error. The message is: ${response.message}`);
			return response;
		});
}

function sendWebAuthnResponse(body){
	return fetch('http://localhost:8080/webauthn/response', {
		method: 'POST',
		credentials: 'include',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify(body),
	})
		.then((response) => response.json())
		.then((response) => {
			if (response.status !== 'ok') 
				throw new Error(`Server responed with error. The message is: ${response.message}`);
			return response;
		});
}

function getGetAssertionChallenge (formBody){
	return fetch('http://localhost:8080/webauthn/login', {
		method: 'POST',
		credentials: 'include',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify(formBody),
	})
		.then((response) => response.json())
		.then((response) => {
			if (response.status !== 'ok') 
				throw new Error(`Server responed with error. The message is: ${response.message}`);
			return response;
		});
};

export {
	getGetAssertionChallenge,
	getMakeCredentialsChallenge,
	sendWebAuthnResponse
};
