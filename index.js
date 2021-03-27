const express = require('express');
const http = require('http');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const router = require('./router');
const mongoose = require('mongoose');
const cors = require('cors');

//DB 
mongoose.connect('mongodb://localhost:27017');

//APP
const app = express();
app.use(morgan('combined'));
app.use(cors());
app.use(bodyParser.json({type: '*/*'}));
router(app);


//SERVER
const port = process.env.port || 3090;
const server = http.createServer(app);
server.listen(port);
console.log('Server listening on:' + port);