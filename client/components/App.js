import React, { useState } from 'react';
import './App.css';
import { Grid, Button, Input } from 'semantic-ui-react';
import { createCreds } from './webauthn';

function App() {
	const [username, setUsername ] = useState('');
	const handleUsernameChange = (e) => {
		setUsername(e.target.value);
	};
	return (
		<div className='App'>
			<header className='App-header'>
				<Grid>
					<Grid.Row>
						<Grid.Column style = {{width: '129px'}}>
							<Input focus placeholder = 'Username' size = 'small' onChange={handleUsernameChange}/>
						</Grid.Column>
					</Grid.Row>
					<Grid.Row>
						<Grid.Column>
							<Button primary size='massive' onClick={createCreds}>
								Register
							</Button>
						</Grid.Column>
					</Grid.Row>
					<Grid.Row>
						<Grid.Column>
							<Button primary  size='massive'>
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
