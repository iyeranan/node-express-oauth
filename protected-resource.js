const express = require("express")
const bodyParser = require("body-parser")
const fs = require("fs")
const { timeout } = require("./utils")
const jwt = require("jsonwebtoken")


const config = {
	port: 9002,
	publicKey: fs.readFileSync("assets/public_key.pem"),
}

const users = {
	user1: {
		username: "user1",
		name: "User 1",
		date_of_birth: "7th October 1990",
		weight: 57,
	},
	john: {
		username: "john",
		name: "John Appleseed",
		date_of_birth: "12th September 1998",
		weight: 87,
	},
}

const app = express()
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/
app.get('/user-info', function (req, res) {
	if (!req.headers.authorization) {
		res.status(401).end();
	} else {
		let payload = req.headers.authorization.slice(7);
		try {
			payload = jwt.verify(payload, config.publicKey, { algorithm: 'RS256' });
			const scopes = payload.scope.split(" ");
			const ret = {};
			scopes.forEach((scope) => {
				ret[scope.slice(11)] = users[payload.userName][scope.slice(11)]
			});
			res.status(200).send(ret);
		} catch (err) {
			res.status(401).end();
		}
		// res.status(200).end();
	}
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes
module.exports = {
	app,
	server,
}
