const mysql = require('mysql2');
const dbCon = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'coffeeshop'
}).promise();

module.exports = dbCon;

