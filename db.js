const pgsql     = require('pgsql');
const { Pool }  = require('pg');
const fs        = require("fs");

/*
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});
*/

//const Pool = require('pg').Pool
/*
// dont forget 'D:\Postgresql15\data\pg_hba.conf'. move the entry 'all all 127.0.0.1/32' to the first place
//localhost
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'postgres',
  password: 'tomcat@14200',
  port: 5432,
  client_encoding: 'utf8',
  //ssl: true,
  max: 20,
  min: 1,
  idleTimeoutMillis: 1000,
})
*/

/*
//'192.168.43.57' dont forget to ad 'host    all        all        192.168.43.57/32 	    scram-sha-256' in 'D:\Postgresql15\data\pg_hba.conf'
// this entry must be the unique entry in 'IPv4 local connections' or preceed 'all all 127.0.0.1/32'
const pool = new Pool({
  user: 'postgres',
  host: '192.168.43.57',
  database: 'postgres',
  password: 'tomcat@14200',
  port: 5432,
  client_encoding: 'utf8',
  //ssl: true,
  max: 20,
  min: 1,
  idleTimeoutMillis: 1000,
})
*/

/*
//Heroku
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});
*/

/*
//Heroku other color db qui marche au 21-05-22
const pool = new Pool({
  connectionString: process.env.HEROKU_POSTGRESQL_PURPLE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});
*/

/*
//Render
const pool = new Pool({
  //connectionString: DATABASE_URL,
   connectionString:process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});
*/

/*
//HelioHost
const pool = new Pool({
  user: 'tomcaty_tomatish',
  host: 'johnny.heliohost.org',
  database: 'tomcaty_Supabase_pgsql',
  password: 'tomcat14200',
  port: 5432,
  client_encoding: 'utf8',
  //ssl: true,
  max: 20,
  min: 1,
  idleTimeoutMillis: 1000,
})
*/


//Render + Aiven + env
const pool = new Pool({
  user: process.env.USER,
  host: process.env.HOST,
  database: process.env.DATABASE,
  password: process.env.PASSWORD,
  port: process.env.PORT,
  client_encoding: 'utf8',
  ssl: {
    rejectUnauthorized: true,
    ca: fs.readFileSync("./ca.pem").toString(),
  },
  max: 20,
  min: 1,
  idleTimeoutMillis: 1000,
});


/*
//Render + Heliohost + env
const pool = new Pool({
  user: process.env.USER1,
  host: process.env.HOST1,
  database: process.env.DATABASE1,
  password: process.env.PASSWORD1,
  port: process.env.PORT1,
  client_encoding: 'utf8',
  max: 20,
  min: 1,
  idleTimeoutMillis: 1000,
});
*/

// Export the pool so it can be used in other files
module.exports = pool;