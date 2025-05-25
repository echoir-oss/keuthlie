const process = require("node:process");
const crypto = require("node:crypto");
const fs = require("node:fs");

const express = require("express");
const argon2 = require("argon2");
const ansi = require("ansi");
const uuid = require("uuid");
const pg = require("pg");

const privateKeyText = fs.readFileSync("./certs/key.pem", "utf-8");
const publicKeyText = fs.readFileSync("./certs/cert.pem", "utf-8");

const privateKey = crypto.createPrivateKey(privateKeyText);
const publicKey = crypto.createPublicKey(publicKeyText);
const config = require("./config.js");

const pool = new pg.Pool(config.pgconf);
const stderr = ansi(process.stderr);
const app = express();

app.use(async (req, res, next) => {
	const start = Date.now();

	res.setHeader("Access-Control-Allow-Origin", "https://staging.echoir.fr, https://admin.staging.echoir.fr, https://sql.admin.echoir.fr");
	res.setHeader("Access-Control-Request-Method", "GET, POST");

	req.on("end", async () => {
		printMethod(req.method);
		printStatusCode(res.statusCode);
		printLatency(Date.now()-start);

		stderr.write(`${req.path}\n`);
	});

	next();
});

app.use(express.json());

async function sleep(ms) {
	await new Promise((a) => setTimeout(a, ms));
	return;
}

function printMethod(method) {
	switch (method.toUpperCase()) {
	case "GET":
		stderr.green().write(method);
		break;
	case "POST":
		stderr.blue().write(method);
		break;
	default:
		stderr.red().write(method);
		break;
	}
	stderr.write(" ").reset();

	return;
}

function printLatency(latency) {
	stderr.brightCyan();
	
	if (latency > 3) {
		stderr.cyan();
	}

	if (latency > 20) {
		stderr.green();
	}

	if (latency > 40) {
		stderr.yellow();
	}

	if (latency > 50) {
		stderr.brightYellow();
	}

	if (latency > 80) {
		stderr.brightRed();
	}

	if (latency > 100) {
		stderr.red();
	}

	if (latency > 250) {
		stderr.black();
	}

	stderr.write(latency.toString()).write("ms ").reset();
}

function printStatusCode(statusCode) {
	const stringCode = statusCode.toString();
	const colour = statusCode / 100;

	stderr.bold();

	switch (colour) {
	case 2:
		stderr.brightGreen();
		break;
	default:
		stderr.brightRed();
		break;
	}

	stderr.write(stringCode).reset().write(" ");
}

async function getPasshash(database, id) {
	const resultA = await database.query("SELECT passhash FROM keuthlie_auth WHERE id = $1", [id]);

	if (resultA.rows.length !== 1) {
		return null;
	}

	return resultA.rows[0].passhash;
}

async function updatePassword(database, id, password) {
	try {
		const soy = ssha512(generateBytes(32));
		const passhash = await argon2.hash(password);
		const resultA = await database.query("UPDATE keuthlie_auth SET passhash = $2 WHERE id = $1;", [id, passhash]);
		const resultB = await database.query("UPDATE keuthlie_auth SET soy = $2 WHERE id = $1;", [id, soy]);

		return true;
	} catch (e) {
		console.error(e);
		return false;
	}
}

async function verifyPassword(database, id, password) {
	const passhash = await getPasshash(database, id);

	if (passhash === null) {
		return false;
	}

	const a = await argon2.verify(passhash, password);
	console.error(a);
	return a;
}

async function isUsernameTaken(database, username) {
	const resultA = await database.query("SELECT username FROM keuthlie_auth WHERE username = $1", [username]);

	if (resultA.rows.length !== 0) {
		return true;
	}

	return false;
}

async function isEmailInUse(database, email) {
	const resultA = await database.query("SELECT email FROM keuthlie_auth WHERE email = $1", [email]);

	if (resultA.rows.length !== 0) {
		return true;
	}

	return false;
}

async function getIdFromEmail(database, email) {
	const resultA = await database.query("SELECT id FROM keuthlie_auth WHERE email = $1", [email]);

	if (resultA.rows.length !== 1) {
		return null;
	}

	return resultA.rows[0].id;
}

async function createUserProfile(database, email, username) {
	const id = uuid.v7();

	await database.query("INSERT INTO keuthlie_auth VALUES ($1, $2, $3, $4, $5)", [id, username, email, "$argon2id$v=19$m=65536,t=3,p=4$LwS1dlmlB4f4sn8dzDfCVw$yq3Junr9JuQfiunAGYY+VIYXLpUCa5F0W4bnoU6flvc", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"]);

	return id;
}

async function getUserSoy(database, id) {
	const resultA = await database.query("SELECT soy FROM keuthlie_auth WHERE id = $1", [id]);

	if (resultA.rows.length !== 1) {
		return null;
	}

	return resultA.rows[0].soy;
}

async function createUser(database, email, username, password) {
	const id = await createUserProfile(database, email, username, password);

	const retA = await updatePassword(database, id, password);
	if (!retA) {
		throw new Error("oh shit!");
	}

	return id;
}

function sha512(data) {
	return crypto.createHash("sha3-512").update(data).digest("hex");
}

function ssha512(data) {
	return sha512(data).toString("hex");
}

function generateBytes(n) {
	return crypto.randomBytes(n);
}

async function createToken(database, id) {
	const soyH = ssha512(await getUserSoy(database, id));
	const dataA = ssha512(generateBytes(64));

	const prepend = `00\$keuthlie\$${id}\$${soyH}\$${dataA}`;
	const signature = signString(prepend);
	const ret = `${prepend}\$${signature}`;

	return ret;
}

async function verifyToken(database, token) {
	const splitThing = token.split("$");

	if (splitThing[0] !== "00") {
		return false;
	}

	if (splitThing.length !== 6) {
		return null;
	}

	const version = splitThing[0];
	const reportedAuthServer = splitThing[1];
	const userId = splitThing[2];
	const soyHashedB = splitThing[3];
	const randomData = splitThing[4];
	const signature = Buffer.from(splitThing[5], "hex");

	const withoutSignature = splitThing.reverse().slice(1).reverse().join("$");

	const valid = crypto.verify("RSA-SHA512", sha512(withoutSignature), publicKey, signature);

	if (!valid) {
		return false;
	}

	const soyHashedA = ssha512(await getUserSoy(database, userId));
	if (soyHashedA !== soyHashedB) {
		return false;
	}

	return true;
}

function signString(stringie) {
	const a = Date.now();
	const signInstance = crypto.createSign("RSA-SHA512");

	signInstance.update(stringie);
	signInstance.end();
	return signInstance.sign(privateKey).toString("hex");
}

app.post("/api/v0/auth/verifyToken", async (req, res, next) => {
	//
});

app.post("/api/v0/auth/register/email", async (req, res, next) => {
	if (typeof req.body?.email !== "string" ||
	    typeof req.body?.password !== "string" ||
	    typeof req.body?.username !== "string") 
	{
		res.status(400);
		res.json({
			error: -5,
			message: "Invalid data provided!"
		});

		return;
	}

	const database = await pool.connect();
	await database.query("BEGIN;");

	try {
		const username = req.body.username;
		const password = req.body.password;
		const email = req.body.email;

		if (password.length <= 8) {
			res.status(403);
			res.json({
				error: -2,
				message: "Password too short!"
			});

			throw new Error("what the fuck!!");
		}

		if (await isUsernameTaken(database, req.body.username)) {
			res.status(403);
			res.json({
				error: -3,
				message: "Username already in use!"
			});

			throw new Error("username taken!!");
		}

		if (await isEmailInUse(database, req.body.email)) {
			res.status(403);
			res.json({
				error: -4,
				message: "E-mail already in use!"
			});

			throw new Error("e-mail taken!!");
		}

		const id = await createUser(database, email, username, password);

		await database.query("COMMIT");

		res.status(200);
		res.json({
			error: 0,
			payload: {
				uuid: id
			}
		});
	} catch (e) {
		await database.query("ROLLBACK;");

		console.error(e);
		// throw new Error("uhm. yeah,  if you see this on the website, please report this with details.");

		res.status(500);
		res.end("uhm. yeah, if you see this on the website, please report this with details. thanks!");

		return;
	} finally {
		database.release();
	}
});

app.post("/api/v0/auth/login/email", async (req, res, next) => {
	if (typeof req.body?.email !== "string" ||
	    typeof req.body?.password !== "string" ||
	    typeof req.body?.service !== "string") 
	{
		res.status(400);
		res.json({
			error: -5,
			message: "Invalid data provided!"
		});

		return;
	}

	const database = await pool.connect();
	await database.query("BEGIN;");

	try {
		const password = req.body.password;
		const service = req.body.service;
		const email = req.body.email;

		if (password.length <= 8) {
			res.status(403);
			res.json({
				error: -2,
				message: "Password too short!"
			});
			throw new Error("what the fuck!!");
		}

		const id = await getIdFromEmail(database, email);
		if (id === null) {
			res.status(403);
			res.json({ error: -5, message: "Invalid data provided!" });
			throw Error("huh buh");
		}

		const valid = await verifyPassword(database, id, password);
		if (!valid) {
			res.status(403);
			res.json({
				error: -1,
				message: "Invalid e-mail or password!"
			});
			throw new Error("buh");
		}

		let allowed = false;
		for (let i = 0; i < config.keuthlie.allowedServices.length; i++) {
			const _service = config.keuthlie.allowedServices[i];

			if (_service === service) {
				allowed = true;
				break;
			}
		}

		if (!allowed) {
			res.status(403);
			res.json({
				error: -6,
				message: "Disallowed service selected!"
			});

			throw new Error("guh");
		}

		const token = await createToken(database, id, req.body.service);

		res.status(200);
		res.json({
			error: 0,
			payload: {
				id,
				token
			}
		});

	} catch (e) {
		await database.query("ROLLBACK;");

		console.error(e);

		res.status(500);
		res.end("uhm. yeah, if you see this on the website, please report this with details. thanks!");

		return;
	} finally {
		database.release();
	}
});

app.use(async (req, res) => {
	res.status(404);
	res.end("404");
});

(async () => {
	process.stderr.write("keuthlie\n");

	app.listen(config.keuthlie.port, () => {
		process.stderr.write(`Listening on ${config.keuthlie.port}\n\n`);
	});
})();
