import './App.css';
import React, { useState, useEffect } from 'react';
import { Grid, Button, Message, Form, Segment, Header } from 'semantic-ui-react';
import { getGetAssertionChallenge, getMakeCredentialsChallenge, sendWebAuthnResponse, getProfile, logout, registerFail } from './webauthn';
import { preformatGetAssertReq, preformatMakeCredReq, publicKeyCredentialToJSON } from '../helpers';

function App() {
	const [errMsg, setErrMsg] = useState('');
	const [email, setEmail ] = useState('');
	const [successMsg, setSuccessMsg] = useState('');
	const [loggedIn, setLoggedIn] = useState(false);
	const [profileData, setProfileData] = useState(null);

	const handleUsernameChange = (e) => {
		setEmail(e.target.value);
	};
	const handleRegister = () => {
		getMakeCredentialsChallenge({email})
			.then((response) => {
				const publicKey = preformatMakeCredReq(response);
				return navigator.credentials.create({ publicKey });
			})
			.then((response) => {
				const makeCredResponse = publicKeyCredentialToJSON(response);
				return sendWebAuthnResponse(makeCredResponse);
			})
			.then((response) => {
				if(response.status === 'ok'){
					setErrMsg('');
					setSuccessMsg('You can now try logging in');
				}
				else
					setErrMsg(response.message);
			})
			.catch(err => {
				registerFail({email})
					.then(() => {
						if(err.response)
							setErrMsg(err.response.data);
						else
							console.log(err);
					});
			});
	};

	const handleLogin = () => {
		getGetAssertionChallenge({email})
			.then((response) => {
				const publicKey = preformatGetAssertReq(response);
				return navigator.credentials.get({ publicKey });
			})
			.then((response) => {
				let getAssertionResponse = publicKeyCredentialToJSON(response);
				return sendWebAuthnResponse(getAssertionResponse);
			})
			.then((response) => {
				if(response.status === 'ok') {
					localStorage.setItem('loggedIn', true);
					setLoggedIn(true);
					setEmail('');
					setSuccessMsg('');
					setErrMsg('');
				} else {
					setSuccessMsg('');
					setErrMsg(response.message);
				}
			})
			.catch(err => {
				if(err.response)
					setErrMsg(err.response.data);
				else
					console.log(err);
			});
	};
	const handleLogout = () => {
		setEmail('');
		logout().then(() => {
			localStorage.removeItem('loggedIn');
			setLoggedIn(false);
			setProfileData(null);
		});
	};

	useEffect(() => {;
		if(localStorage.getItem('loggedIn'))
			setLoggedIn(true);
		if(loggedIn)
			getProfile()
				.then(data => {
					setProfileData(data);
				})
				.catch(err => {
					setErrMsg(err.response.data);
					localStorage.removeItem('loggedIn');
				});
	}, [loggedIn]);

	return (
		<div className='App-header'>
			<Grid container textAlign='center' verticalAlign='middle'>
				<Grid.Column style={{ maxWidth: 450, minWidth: 300 }}>
					<Header as='h2' textAlign='center' style={{ color: 'white'}}>
						WebAuthn Demo
					</Header>
					{!loggedIn ?
						<Form size='large'>
							{errMsg && <Message negative icon='warning sign' size='mini' header={errMsg}/>}
							{successMsg && <Message positive icon='thumbs up' size='mini' header={successMsg}/>}
							<Segment>
								<Form.Input 
									fluid
									icon='user'
									iconPosition='left'
									placeholder='Username'
									onChange={handleUsernameChange}
								/>
								<Button 
									fluid 
									size='large' 
									onClick={handleRegister} 
									style={{ 
										marginTop: 8,
										color: 'white',
										backgroundColor: '#19857b'
									}}
									disabled={!email}
								>
									Register
								</Button>
								<Button 
									fluid 
									size='large'
									onClick={handleLogin} 
									style={{ 
										marginTop: 8,
										color: 'white',
										backgroundColor: '#19857b'
									}}
									disabled={!email}
								>
									Login
								</Button>
							</Segment>
						</Form>
						:
						<Segment style={{ overflowWrap: 'break-word'}}>
							{profileData &&
								<>
									<Header as='h3' textAlign='center'>
										Hi {profileData.name}
									</Header>
									<Header as='h4' textAlign='center'>
										Your profile information
									</Header>
									<strong>ID: </strong>{profileData.id}
									<br/>
									<strong>Credential information:</strong>
									<br/>
									<strong>Format: </strong>{profileData.authenticators[0].fmt}
									<br/>
									<strong>Public key: </strong>
									<br/>
									<div style={{
										maxWidth: 300,
										overflowWrap: 'break-word',
										marginLeft: '25%',
										marginRight: '25%'
									}}>
										{profileData.authenticators[0].publicKey}
									</div>
									<Button 
										fluid 
										size='large'
										onClick={handleLogout} 
										style={{ 
											marginTop: 8,
											color: 'white',
											backgroundColor: '#19857b'
										}}
									>
										Logout
									</Button>
								</>
							}
						</Segment>
					}
				</Grid.Column>
			</Grid>
		</div>
	);
}

export default App;
