const fs = require("fs")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils")

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/
app.get('/authorize', function (req, res) {
	// const clientId = req.param('client_id');
	let matchedClient;
	// const reqScopes = req.query.scope.split(" ");

	for (let key in clients) {
		if (req.param('client_id') === key) {
			matchedClient = clients[key];
			break;
		}
	}
	if (!matchedClient || !req.query.scope || !containsAll(matchedClient.scopes, req.query.scope.split(" "))) {
		res.status(401).end();
	} else {
		const reqId = randomString();
		requests[reqId] = req.query;
		res.render('login', { "client": matchedClient, "scope": req.query.scope, "requestId": reqId });
		// res.status(200).end();
	}
})

app.post('/approve', function (req, res) {
	const requestId = req.body.requestId;
	if (!users[req.body.userName] || (users[req.body.userName] !== req.body.password) || !requests[requestId]) {
		res.status(401).end();
	} else {
		const clientReq = requests[requestId];
		delete requests[requestId];
		const key = randomString();
		authorizationCodes[key] = { "clientReq": clientReq, "userName": req.body.userName }

		const myURL = new URL(clientReq.redirect_uri);
		myURL.searchParams.append('code', key);
		myURL.searchParams.append('state', clientReq.state);

		res.redirect(myURL.href);
	}
	// res.send('POST request to the homepage')
})

app.post('/token', function (req, res) {
	if (!req.headers.authorization) {
		res.status(401).end();
	} else {
		const client = decodeAuthCredentials(req.headers.authorization);

		if (!clients[client.clientId] || (clients[client.clientId].clientSecret !== client.clientSecret) || !authorizationCodes[req.body.code]) {
			res.status(401).end();
		} else {
			const obj = authorizationCodes[req.body.code];
			delete authorizationCodes[req.body.code];
			const token = jwt.sign({ userName: obj.userName, scope: obj.clientReq.scope }, config.privateKey, { algorithm: 'RS256' });
			res.status(200).send({ "access_token": token, "token_type": 'Bearer' });
		}
	}
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
