const pg = require("pg");

const config = require("../config.js");

const dbpool = new pg.Pool(config.pgconf);

(async () => {
	process.stderr.write("pool... ");
	const database = await dbpool.connect();
	process.stderr.write("OK\n");

	async function runSQL(query) {
		process.stderr.write(query);
		await database.query(query);
		process.stderr.write("\n");
	}

	await runSQL("DROP TABLE IF EXISTS keuthlie_auth");
	await runSQL("CREATE TABLE keuthlie_auth(id TEXT PRIMARY KEY, username TEXT, email TEXT, passhash TEXT, soy TEXT)");

	process.stderr.write("releasing... ");
	await database.release();
	process.stderr.write("OK\nClosing pool... ");
	await dbpool.end();
	process.stderr.write("OK\n");
})();
