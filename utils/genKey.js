const crypto = require("node:crypto");
const fs = require("node:fs");

(() => {
	process.stderr.write("Generating RSA key... ");
	const keyPair = crypto.generateKeyPairSync("rsa", {
		modulusLength: 8192
	});
	process.stderr.write("OK\n");

	const publicKeyText = keyPair.publicKey.export({
		type: "spki",
		format: "pem"
	});
	const privateKeyText = keyPair.privateKey.export({
		type: "pkcs8",
		format: "pem"
	});

	fs.writeFileSync("./certs/cert.pem", publicKeyText);
	fs.writeFileSync("./certs/key.pem", privateKeyText);
})();
