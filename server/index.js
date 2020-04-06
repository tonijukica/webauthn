const express = require('express');

const app = express();

app.use(express.json({}));

app.use(express.static('dist'));

app.get('/', (req, res) => {
	res.send('Express server is up and running');
});

app.listen(8080, () => {
	console.log('Server listening on http://localhost:8080');
});
