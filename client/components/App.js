import React, { useState } from 'react';
import './App.css';
import { Grid, Button, Input } from 'semantic-ui-react';
import { getGetAssertionChallenge, getMakeCredentialsChallenge, sendWebAuthnResponse } from './webauthn';
import { preformatGetAssertReq, preformatMakeCredReq, publicKeyCredentialToJSON } from '../helpers';

function App() {
	const [email, setEmail ] = useState('');
	const handleUsernameChange = (e) => {
		setEmail(e.target.value);
	};
	const handleRegister = () => {
		if(!email){
			console.log('missing email');
		}
		getMakeCredentialsChallenge({email})
			.then((response) => {
				console.log('1');
				const publicKey = preformatMakeCredReq(response);
				console.log(publicKey);
				console.log('1.5');
				return navigator.credentials.create({ publicKey });
			})
			.then((response) => {
				console.log(response);
				console.log('2');
				const makeCredResponse = publicKeyCredentialToJSON(response);
				console.log(makeCredResponse);
				console.log('2.5');
				return sendWebAuthnResponse(makeCredResponse);
			})
			.then((response) => {
				console.log('3');
				if(response.status === 'ok')
					alert('All ok ');
				else
					alert(`Server responed with error. The message is: ${response.message}`);
			})
			.catch(err => console.log(err));
	};
	const handleLogin = () => {
		if(!email){
			console.log('missing email');
		}

		getGetAssertionChallenge({email})
			.then((response) => {
				console.log(response);
				const publicKey = preformatGetAssertReq(response);
				return navigator.credentials.get({ publicKey });
			})
			.then((response) => {
				let getAssertionResponse = publicKeyCredentialToJSON(response);
				return sendWebAuthnResponse(getAssertionResponse);
			})
			.then((response) => {
				if(response.status === 'ok') {
					alert('Logged in User');
				} else {
					alert(`Server responed with error. The message is: ${response.message}`);
				}
			})
			.catch((error) => console.log(error));
	};

	return (
		<div className='App'>
			<header className='App-header'>
				<Grid>
					<Grid.Row>
						<Grid.Column style = {{width: '129px'}}>
							<Input focus placeholder = 'Email' size = 'small' onChange={handleUsernameChange}/>
						</Grid.Column>
					</Grid.Row>
					<Grid.Row>
						<Grid.Column>
							<Button primary size='massive' onClick={handleRegister}>
								Register
							</Button>
						</Grid.Column>
					</Grid.Row>
					<Grid.Row>
						<Grid.Column>
							<Button primary  size='massive' onClick={handleLogin}>
								Login
							</Button>
						</Grid.Column>
					</Grid.Row>
				</Grid>
			</header>
		</div>
	);
}

export default App;
