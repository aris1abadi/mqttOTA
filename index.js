
const express = require('express');
const app = express();
const http = require('http').createServer(app);
const path = require('path');
const fs = require('fs');
const bodyParser = require('body-parser');
const multer = require('multer');
const session = require('express-session');
const upload = multer({
	dest: 'upload/'
});

const mqttPrefix = "abadinet"

const mqtt = require("mqtt");

//const WebSocket = require('ws');
//const wss = new WebSocket.Server({
//	server: http
//});
const os = require('os');
const { match } = require('assert');
//const expressWs = require('express-ws'); 
//expressWs(app);
const lastCommands = {};

// Store registered devices and their firmware versions, MAC addresses, Wi-Fi signal strengths, and IP addresses in memory
const registeredDevices = new Map();

// Store firmware updates flags for devices
const firmwareUpdates = {};

// Store last heartbeat time for each device
const lastHeartbeatTime = new Map();

// Timeout duration for considering a device offline (in milliseconds)
const heartbeatTimeout = 20000;

const subMqtt = mqttPrefix + "-out/#"
const pubMqtt = mqttPrefix + "-in/"
let clientId = 'abadinet' + Math.floor(Math.random() * 1000);
//const host = 'ws://abadinet.my.id:2020'
//const host = 'wss://node-red.balingtansmart.my.id/ws'    
//const host = 'wss://' + get(brokerUseStore) + '/mqtt:' + get(brokerPortUseStore); 
const host = 'wss://mqtt.eclipseprojects.io/mqtt:443'

const options = {
	keepalive: 30,
	clientId,
	protocolId: 'MQTT',
	protocolVersion: 4,
	clean: true,
	reconnectPeriod: 5000,
	connectTimeout: 30 * 1000,
	will: {
		topic: 'WillMsg',
		payload: 'Connection Closed abnormally..!',
		qos: 0,
		retain: false
	},
	rejectUnauthorized: false
}

//console.log('connecting mqtt client')
const client = mqtt.connect(host, options)


client.on('error', (err) => {
	console.log(err)
	client.end()
})
client.on('disconnect', () => {	
	console.log('client disconect')
	client.end()
	setTimeout(()=>client.reconnect(),5000);

})

client.on('connect', () => {
	console.log('client connected:' + clientId)
	client.subscribe(subMqtt, { qos: 0 })
	let pubStatus = pubMqtt + "/status"

	client.publish(pubStatus, clientId, { qos: 0, retain: false })
	//kirimMsg("kontrol", 0, "getAllStatus", "1")
})

client.on('message', (topic, message, packet) => {
	cekMqttMsg(topic, message);
	//console.log("topic:" + topic + "\nmsg:" + message)
})

client.on('close', () => {
	console.log(clientId + ' disconnected')
})

function kirimKeDevice(deviceId, cmd, msg) {
	//topic abadinet-in/SPxxxx/serverUpdate/0/cmd
	const pubTopic = pubMqtt + deviceId + '/serverUpdate/0/' + cmd;
	client.publish(pubTopic, msg);
}


function cekMqttMsg(topic, msg) {
	//msq String postData = String(hostName) + "\n" + firmwareVersion + "\n" + macAddress + "\n" + wifiSignalStrength + "\n" + WiFi.localIP().toString() + '\n';
	//topic >> abadinet-out/SP4399/serverUpdate/0/register
	const splitTopic = topic.split('/');
	if (splitTopic[2] === 'serverUpdate') {
		if (splitTopic[4] === 'register') {
			console.log('register >>' + msg);
			
			const dta = msg.toString();
			if (registerDevice(dta)) {
				kirimKeDevice(splitTopic[1], 'register', 'register sukses')
			} else {
				kirimKeDevice(splitTopic[1], 'register', 'register gagal')
			}
			
		}
	}else if(splitTopic[2] === 'kontrol'){
		if (splitTopic[4] === 'heartBeat') {
			lastHeartbeatTime.set(splitTopic[1], Date.now());
			console.log('heartBeat ;' + msg.toString())

			cekUpdateAvilable(splitTopic[1]);
		}
	}
}


// Modify your app.post('/firmwareInitiated') endpoint as follows:
app.post('/firmwareInitiated', (req, res) => {
	const message = req.body;
	const hostName = req.query.hostName; // Extract the hostname from the query parameter

	console.log(`Received "Hello" message from ${hostName}`);

	// Broadcast the "Hello" message with the hostname to all connected clients (HTML pages)
	/*
	wss.clients.forEach((client) => {
		if (client.readyState === WebSocket.OPEN) {
			client.send(`Received Firmware OTA by ${hostName}`);
		}
	});
	*/

	res.sendStatus(200);
});

// WebSocket connection
/*
wss.on('connection', (ws) => {
	console.log('Client connected');

	ws.on('message', (message) => {
		console.log('Received message from client:', message);
		// Broadcast the received message to all connected clients
		wss.clients.forEach((client) => {
			if (client !== ws && client.readyState === WebSocket.OPEN) {
				client.send(message);
			}
		});
	});

	ws.on('close', () => {
		console.log('Client disconnected');
	});
});
*/



// Create a new endpoint to serve the WebSocket IP and port dynamically
/*
app.get('/getWebSocketAddress', (req, res) => {
	// Get the actual IP address of the server
	const serverIpAddress = getServerIpAddress();

	// Get the actual port number that the server is listening on
	const serverPort = getServerPort();

	// Provide the IP and port of the WebSocket server
	const wsAddress = {
		ip: serverIpAddress,
		port: serverPort
	};

	res.json(wsAddress);
});
*/
// Function to get the server's IP address
function getServerIpAddress() {
	const networkInterfaces = os.networkInterfaces();
	for (const interfaceName in networkInterfaces) {
		const networkInterface = networkInterfaces[interfaceName];
		for (const interfaceInfo of networkInterface) {
			if (interfaceInfo.family === 'IPv4' && !interfaceInfo.internal) {
				return interfaceInfo.address;
			}
		}
	}
	// If the IP address is not found, return localhost as a fallback
	return '127.0.0.1';
}

// Function to get the server's port number
function getServerPort() {
	return http.address().port;
}

// Serve the login.html file
app.get('/', (req, res) => {
	res.sendFile(path.join(__dirname, 'login.html'));
});

// Middleware to parse request body
app.use(bodyParser.urlencoded({
	extended: true
}));
app.use(bodyParser.json());

// Middleware to handle sessions
app.use(session({
	secret: 'your-secret-key',
	resave: false,
	saveUninitialized: false,
}));

// The hardcoded username and password (replace these with your actual credentials)
const validUsername = 'abadinet';
const validPassword = 'indosat123';

app.post('/login', (req, res) => {
	const {
		username,
		password
	} = req.body;

	console.log('Received login request:', {
		username,
		password
	}); // Debug log to check received data

	if (username === validUsername && password === validPassword) {
		// Set a session variable to indicate successful login
		req.session.isLoggedIn = true;
		res.redirect('/index.html'); // Redirect to the index.html page
	} else {
		console.log('Invalid login attempt:', {
			username,
			password
		}); // Debug log for invalid login attempts
		res.status(401).send('Invalid username or password.');
	}
});

// Endpoint to handle password authentication
app.post('/authenticate', (req, res) => {
	const {
		password
	} = req.body;

	// Replace 'your-password' with the correct password for authentication
	const validPassword = 'indosat123';

	if (password === validPassword) {
		res.sendStatus(200); // Password is correct
	} else {
		res.sendStatus(401); // Password is incorrect
	}
});

// Middleware to protect access to index.html
app.get('/index.html', (req, res, next) => {
	if (req.session.isLoggedIn) {
		res.sendFile(path.join(__dirname, 'index.html'));
	} else {
		res.redirect('/');
	}
});

// Middleware to parse request body
app.use(bodyParser.text());

// Endpoint to handle logout
app.post('/logout', (req, res) => {
	req.session.isLoggedIn = false; // Clear the isLoggedIn session variable to indicate logout
	res.sendStatus(200);
});

// Endpoint to handle ESP8266 registration
app.post('/register', (req, res) => {
	const dta = req.body.trim();
	const data = dta.split('\n');
	

	if (registerDevice(dta)) {
		res.status(200).send('Registration successful.');
	} else {
		res.status(400).send('Bad Request.');
	}
	/*
		// Check if the device is already registered
		if (registeredDevices.has(hostName)) {
			// Check if firmware version has changed
			if (registeredDevices.get(hostName).firmwareVersion !== firmwareVersion) {
				console.log(`Firmware version changed for ${hostName}. Re-registering...`);
				firmwareUpdates[hostName] = true;
			}
		} else {
			console.log(`Registering ${hostName}`);
		}
	
		// Store device information including hostname, firmware version, MAC address, Wi-Fi signal strength, and IP address
		registeredDevices.set(hostName, {
			hostName,
			firmwareVersion,
			macAddress,
			wifiSignalStrength,
			ipAddress
		});
	
		console.log('Registered devices:', Array.from(registeredDevices.entries()));
		res.status(200).send('Registration successful.');
	
		// Save registered devices to the text file
		saveRegisteredDevicesToFile();
		*/
});

function registerDevice(dta) {
	const data = dta.split('/')
	const hostName = data[0];
	const firmwareVersion = data[1];
	const macAddress = data[2];
	const wifiSignalStrength = parseInt(data[3]); // Parse Wi-Fi signal strength as an integer
	const ipAddress = data[4]; // Get the IP address sent by the ESP8266

	if (!hostName || !firmwareVersion || !macAddress || isNaN(wifiSignalStrength) || !ipAddress) {

		return false;
	}

	// Check if the device is already registered
	if (registeredDevices.has(hostName)) {
		// Check if firmware version has changed
		if (registeredDevices.get(hostName).firmwareVersion !== firmwareVersion) {
			console.log(`Firmware version changed for ${hostName}. Re-registering...`);
			firmwareUpdates[hostName] = true;
		}
	} else {
		console.log(`Registering ${hostName}`);
	}

	// Store device information including hostname, firmware version, MAC address, Wi-Fi signal strength, and IP address
	registeredDevices.set(hostName, {
		hostName,
		firmwareVersion,
		macAddress,
		wifiSignalStrength,
		ipAddress
	});

	console.log('Registered devices:', Array.from(registeredDevices.entries()));

	//res.status(200).send('Registration successful.');
	// Save registered devices to the text file
	saveRegisteredDevicesToFile();
	return true
}

function cekUpdateAvilable(hostName){
	console.log('update cek ' + hostName)
	const updateAvailable = firmwareUpdates[hostName] === true;
	if (updateAvailable) {
		// Clear the update flag if update is available
		firmwareUpdates[hostName] = false;
		kirimKeDevice(hostName,'updateStatus','Update Available')
		return true;
		//res.status(200).send('Update Available');
	} else {
		kirimKeDevice(hostName,'updateStatus','No Update Available')
		return false;
		//res.status(204).send('No Update Available');
	}
}

// Endpoint to fetch registered devices
app.get('/getDevices', (req, res) => {
	res.json(Array.from(registeredDevices.keys()));
});

// Endpoint to fetch firmware version for a specific device
app.get('/getFirmwareVersion', (req, res) => {
	const hostName = req.query.hostName;
	if (!hostName) {
		res.status(400).send('Bad Request.');
		return;
	}

	const deviceInfo = registeredDevices.get(hostName);
	if (deviceInfo) {
		res.status(200).send(deviceInfo.firmwareVersion);
	} else {
		res.status(404).send('Firmware version not found.');
	}
});

// Endpoint to handle firmware upload
app.post('/upload', upload.single('firmwareFile'), (req, res) => {
	const hostName = req.query.hostName;
	if (!hostName) {
		res.status(400).send('Bad Request.');
		return;
	}

	if (!req.file) {
		res.status(400).send('No file uploaded.');
		return;
	}

	const filePath = path.join(__dirname, `upload/${hostName}_firmware.bin`);
	fs.renameSync(req.file.path, filePath);

	console.log(`Received firmware binary for ${hostName}.`);
	res.status(200).send('Firmware upload successful.');

	// Set the firmware update flag for the device
	firmwareUpdates[hostName] = true;
});

// Endpoint to check firmware update status
app.get('/updateStatus', (req, res) => {
	const hostName = req.query.hostName;
	if (!hostName) {
		res.status(400).send('Bad Request.');
		return;
	}

	// Check if the firmware update flag is set for the device
	if(cekUpdateAvilable(hostName)){
		res.status(200).send('Update Available');
	}else{
		res.status(204).send('No Update Available');
	}
	/*
	const updateAvailable = firmwareUpdates[hostName] === true;
	if (updateAvailable) {
		// Clear the update flag if update is available
		firmwareUpdates[hostName] = false;
		res.status(200).send('Update Available');
	} else {
		res.status(204).send('No Update Available');
	}
	*/
});

// Endpoint to handle heartbeat from ESP8266
app.post('/heartbeat', (req, res) => {
	const hostName = req.body;
	if (!hostName) {
		res.status(400).send('Bad Request.');
		console.log("hearbeat bad request")
		return;
	}

	// Update the last heartbeat time for the device
	lastHeartbeatTime.set(hostName, Date.now());

	res.status(200).send(`Heartbeat received from ${hostName}.`);
});

// Endpoint to flush all registered devices
app.post('/flushAllDevices', (req, res) => {
	registeredDevices.clear();
	lastHeartbeatTime.clear();
	saveRegisteredDevicesToFile(); // Save the empty registered devices to the file
	res.sendStatus(200);
});

// Endpoint to fetch online status and firmware version for all registered devices
app.get('/getOnlineStatus', (req, res) => {
	const deviceStatusList = [];
	const now = Date.now(); // Get the current timestamp

	registeredDevices.forEach((deviceInfo, device) => {
		const lastHeartbeat = lastHeartbeatTime.get(device);
		const online = lastHeartbeat && now - lastHeartbeat <= heartbeatTimeout; // Check if the device is online based on the last heartbeat time
		deviceStatusList.push({
			device: device,
			online: online,
			firmwareVersion: deviceInfo.firmwareVersion,
			macAddress: deviceInfo.macAddress,
			wifiSignalStrength: deviceInfo.wifiSignalStrength,
			ipAddress: deviceInfo.ipAddress
		});
	});

	res.json(deviceStatusList);
});

// Endpoint to serve the firmware binary file
app.get('/upload/:fileName', (req, res) => {
	const fileName = req.params.fileName;
	const filePath = path.join(__dirname, `upload/${fileName}`);
	if (fs.existsSync(filePath)) {
		// Set appropriate headers for binary file download
		res.setHeader('Content-Type', 'application/octet-stream');
		res.setHeader('Content-Disposition', `attachment; filename=${fileName}`);
		res.setHeader('Content-Length', fs.statSync(filePath).size); // Set Content-Length header
		fs.createReadStream(filePath).pipe(res);
	} else {
		res.status(404).send('Firmware not found.');
	}
});

app.post('/sendSerialData', (req, res) => {
	const {
		hostName
	} = req.query;
	const serialData = req.body; // Assuming the serial data is sent in the request body

	// Process the received serial data as needed
	console.log(`Received serial data from ${hostName}: ${serialData}`);

	// Send a response if necessary (optional)
	res.send('Serial data received successfully');
});

// Endpoint for the client to send a command
app.post('/sendCommand', (req, res) => {
	const deviceHostName = req.body.hostName;
	const command = req.body.command;

	if (!deviceHostName) {
		res.status(400).send('Bad Request.');
		return;
	}

	// If the command is received from the ESP8266, store it in lastCommands object
	if (command) {
		lastCommands[deviceHostName] = command;
		console.log(`Received command "${command}" from ESP8266 for ${deviceHostName}`);
	} else {
		console.log(`Received command "${lastCommands[deviceHostName]}" from client for ${deviceHostName}`);
	}

	// Send the command to the client
	res.status(200).send(lastCommands[deviceHostName]);
});

// Endpoint for the ESP8266 to request a command
app.get('/getCommand', (req, res) => {
	const deviceHostName = req.query.hostName;

	// Send the last received command for the specific hostName to the ESP8266
	res.status(200).send(lastCommands[deviceHostName] || '');

	// Clear the lastCommand for the specific hostName after sending it to the ESP8266
	delete lastCommands[deviceHostName];
});

// Start the server
const PORT = 2200;
http.listen(PORT, () => {
	// Load registered devices from the text file
	loadRegisteredDevicesFromFile();

	console.log(`Server is running on port ${PORT}`);
});

// Periodically check for offline devices and remove them from the lastHeartbeatTime map
setInterval(() => {
	const now = Date.now();
	lastHeartbeatTime.forEach((heartbeatTime, device) => {
		if (now - heartbeatTime > heartbeatTimeout) {
			lastHeartbeatTime.delete(device); 
		}
	});
}, 1000);

// Function to load registered devices from the text file and populate the `registeredDevices` map
function loadRegisteredDevicesFromFile() {
	const filePath = path.join(__dirname, 'registered_devices.txt');

	fs.readFile(filePath, 'utf8', (err, data) => {
		if (!err) {
			try {
				const devices = JSON.parse(data);
				devices.forEach((device) => {
					registeredDevices.set(device.hostName, device);
				});
				console.log('Registered devices loaded successfully.');
			} catch (error) {
				console.error('Error parsing registered devices file:', error.message);
			}
		} else {
			console.error('Error reading registered devices file:', err.message);
		}
	});
}

// Function to save registered devices to the text file
function saveRegisteredDevicesToFile() {
	const devices = Array.from(registeredDevices.values());
	const filePath = path.join(__dirname, 'registered_devices.txt');

	fs.writeFile(filePath, JSON.stringify(devices, null, 2), (err) => {
		if (err) {
			console.error('Error saving registered devices to file:', err.message);
		} else {
			console.log('Registered devices saved successfully.');
		}
	});
}

// Add a new endpoint to fetch the server version
app.get('/getServerVersion', (req, res) => {
	const serverVersion = "1.0.3"; // Replace this with your actual server version
	res.send(serverVersion);
});