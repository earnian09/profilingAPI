const express = require('express');
const bodyParser = require('body-parser');

const app = express(); // Runs the server
const port = 3000;
const mysql = require('mysql2'); // Connects to the database
const { filter } = require('rxjs');
const { log } = require('@angular-devkit/build-angular/src/builders/ssr-dev-server');
app.use(bodyParser.json());
const { google } = require('googleapis');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Security
const cors = require('cors');
const bcrypt = require('bcrypt');
const saltRounds = 10; // Number of salt rounds to use
const crypto = require('crypto'); // used to random generate jwt secret
const jwt = require('jsonwebtoken');
const JWT_SECRET = crypto.randomBytes(64).toString('hex');

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(cors())


// app.use(cors({
//     origin: 'https://eployeeprofilinghub.com', // use your actual domain name (or localhost), using * is not recommended
//     methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'],
//     allowedHeaders: ['Content-Type', 'Origin', 'X-Requested-With', 'Accept', 'x-client-key', 'x-client-token', 'x-client-secret', 'Authorization', 'Access-Control-Allow-Origin'],
//     credentials: true
// }))
// app.options('*, cors()')


// const db = mysql.createConnection({
//     host: 'localhost',
//     user: 'root',
//     password: '',
//     database: 'profiling',
// });
const db = mysql.createConnection({
    host: 'profilingdatabase.c70w002qw0l1.us-east-1.rds.amazonaws.com',
    user: 'admin',
    password: 'testing123',
    database: 'profiling',
});


function handleDisconnect() {
    db.connect((err) => {
        if (err) {
            console.error('Error connecting to MySQL database:', err);
            setTimeout(handleDisconnect, 2000); // Retry connection after 2 seconds
        } else {
            console.log('Connected to MySQL database');
        }
    });

    db.on('error', (err) => {
        console.error('Database error:', err);
        if (err.code === 'PROTOCOL_CONNECTION_LOST') {
            console.log('Reconnecting to the database...');
            handleDisconnect(); // Reconnect if connection is lost
        } else {
            throw err;
        }
    });
}
handleDisconnect();

const verifyToken = (req, res, next) => {
    const token = req.headers.authorization;

    if (!token) {
        return res.status(403).send({ auth: false, message: 'No token provided.' });
    }

    jwt.verify(token.replace('Bearer ', ''), JWT_SECRET, function (err, decoded) {
        if (err) {
            // Check if the error is because the token has expired
            if (err.name === "TokenExpiredError") {
                return res.status(401).send({ auth: false, expired: true, message: 'Token has expired.' });
            }
            return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });
        }

        // If everything is good, save to request for use in other routes
        req.username = decoded.id;
        next();
    });
};


// Read
app.post('/read', verifyToken, (req, res) => {

    const emp_ID = req.body.emp_ID;
    const page = req.body.page;
    // expects_Array means if the request expects many values that will be looped in the front end.
    expects_Array = false;

    var sql = 'SELECT * FROM ';
    // Check which page to display; grabs option from front end then selects respective table
    switch (page) {
        case 'employeeinfo':
            sql += `tbl_info`;
            break;
        case 'certification':
            sql += `tbl_certification`;
            expects_Array = true;
            break;
        case 'dependencies':
            sql += `tbl_dependencies`;
            expects_Array = true;
            break;
        case 'organizations':
            sql += `tbl_org`;
            expects_Array = true;
            break;
        case 'accountingdetails':
            sql += `tbl_accounting_details`;
            break;
        case 'education':
            sql += `tbl_education`;
            break;
        case 'teachingloads':
            sql += `tbl_teaching_loads`;
            expects_Array = true;
            break;
        case 'workexperience':
            sql += `tbl_experience`;
            expects_Array = true;
            break;
        case 'employeedetails':
            sql += `tbl_details`;
            break;
        case 'skills':
            sql += `tbl_skills`;
            expects_Array = true;
            break;
        case 'personalcontact':
            sql += `tbl_personal_contact`;
            break;
        case 'provincialcontact':
            sql += `tbl_provincial_contact`;
            expects_Array = true;
            break;
        case 'emergency':
            sql += `tbl_emergency`;
            break;
        case 'loginDetails':
            sql += `tbl_login`;
            break;
        default:
            console.log('Unknown Error');
    }
    sql += ` WHERE emp_ID = ${emp_ID}`

    db.query(sql, function (error, result) {
        if (error) {
            console.log("Error:", error);
            res.status(500).send("Internal Server Error");
        } else {
            if (expects_Array == false) {
                // if the display only needs one entry
                res.send(result[0]);
            }
            else if (expects_Array == true) {
                // if the display needs multiple entries, loopable
                res.send(result);
            }
        }
    });
});

// Read All Tables, used for exporting
app.post('/readAllTables', verifyToken, (req, res) => {

    const emp_ID = req.body.emp_ID;
    const mode = req.body.mode;
    const department = req.body.department;

    tables = [
        "tbl_info", 
        "tbl_certification",
        "tbl_dependencies",
        "tbl_org",
        "tbl_accounting_details",
        "tbl_education",
        "tbl_teaching_loads",
        "tbl_experience",
        "tbl_details",
        "tbl_skills",
        "tbl_personal_contact",
        "tbl_provincial_contact",
        "tbl_emergency",
    ]

    var resultData = {}; // Object to store results with table names as keys

    // Loop through tables array
    tables.forEach(function (table) {
        var expects_Array = ["tbl_dependencies", "tbl_org", "tbl_certification", "tbl_skills",
            "tbl_teaching_loads", "tbl_experience", "tbl_provincial_contact"].includes(table);

        var sql = `SELECT * FROM ${table}`;

        if (department != "not_department") {
            sql += ` WHERE emp_ID IN 
            (SELECT emp_ID FROM tbl_details WHERE department = '${department}')`;
        }

        // Single mode is for one user to be exported
        if (mode == "single") {
            sql += ` WHERE emp_ID = ${emp_ID}`;
        }

        db.query(sql, function (error, result) {
            if (error) {
                console.log(`Error querying ${table}:`, error);
                res.status(500).send("Internal Server Error");
            } else {
                // Single mode is for one user to be exported
                if (mode == "single") {
                    if (expects_Array === false) {
                        // If the display only needs one entry
                        resultData[table] = result[0];
                    } else if (expects_Array === true) {
                        // If the display needs multiple entries, loopable
                        resultData[table] = result;
                    }
                }
                // Multiple mode is for multiple users to be exported
                else if (mode == "multiple") {
                    resultData[table] = result;
                }

                // Check if all tables have been queried
                if (Object.keys(resultData).length === tables.length) {
                    // Send the resultData object as a JSON response
                    res.json(resultData);
                }
            }
        });
    });
});

// Read Item ID
// This code is used for accessing an individual item of an array aka loopable component
app.post('/readItem', verifyToken, (req, res) => {

    const item_ID = req.body.item_ID;
    const table_primary_key = req.body.table_primary_key;
    const page = req.body.page;
    // expects_Array means if the request expects many values that will be looped in the front end.

    var sql = 'SELECT * FROM ';
    // Check which page to display; grabs option from front end then selects respective table
    switch (page) {
        case 'dependencies':
            sql += `tbl_dependencies`;
            break;
        case 'certification':
            sql += `tbl_certification`;
            break;
        case 'organizations':
            sql += `tbl_org`;
            break;
        case 'teachingloads':
            sql += `tbl_teaching_loads`;
            break;
        case 'workexperience':
            sql += `tbl_experience`;
            break;
        case 'skills':
            sql += `tbl_skills`;
            break;
        // Contact
        case 'provincialcontact':
            sql += `tbl_provincial_contact`;
            break;
        default:
            console.log('Unknown Error');
    }
    sql += ` WHERE ${table_primary_key} = ${item_ID}`


    db.query(sql, function (error, result) {
        if (error) {
            console.log("Error:", error);
            res.status(500).send("Internal Server Error");
        } else {
            res.send(result[0]);
        }
    });
});

// Get All Employees, relevant for Admins
app.get('/getAllEmployees/:department', verifyToken, (req, res) => {
    const department = req.params.department;

    var sql = `
        SELECT tbl_info.*, tbl_details.department
        FROM tbl_info
        JOIN tbl_details ON tbl_info.emp_ID = tbl_details.emp_ID
        WHERE tbl_info.emp_ID IN (
            SELECT tbl_details.emp_ID
            FROM tbl_details`;

    // Check if the user is not the super admin
    // Not "All" means the user is not the super admin
    // If it is, then return all users
    if (department !== "All") {
        console.log("Not the admin, setting department...");
        sql += ` WHERE department='${department}'`;
    }

    sql += `)`;

    db.query(sql, function (error, result) {
        if (error) {
            console.log("Error:", error);
            res.status(500).send("Internal Server Error");
        } else {
            res.send(result);
        }
    });
});

app.post('/login', (req, res) => {
    res.set('Access-Control-Allow-Origin');
    const username = req.body.username;
    const password = req.body.password;

    var sql = `SELECT * FROM tbl_login WHERE username = '${username}'`;

    db.query(sql, function (error, result) {
        if (error) {
            console.log("Error:", error);
            // Handle database errors
            res.status(500).send("Database error");
        } else {
            // Check if user is found
            if (result.length > 0) {
                const hashedPassword = result[0].password;
                // Compare hashed password with provided password
                bcrypt.compare(password, hashedPassword, function (err, passwordMatch) {
                    if (err) {
                        console.log("Error:", err);
                        res.status(500).send("Error comparing passwords");
                    } else if (passwordMatch) {
                        // Passwords match, user is authenticated

                        // Generate JWT token
                        const token = jwt.sign({ username: username }, JWT_SECRET, { expiresIn: '1h' });
                        console.log(`token: ${token}`);
                        res.json({ emp_ID: result[0].emp_ID, token });
                    } else {
                        // Passwords don't match
                        res.status(401).send("Incorrect password");
                    }
                });
            } else {
                // Handle case where user is not found
                res.status(404).send("User not found");
            }
        }
    });
});

// Update or Add Values
app.put('/update', verifyToken, (req, res) => {
    const updateBody = req.body;

    // Code relevant to commas in sql query
    let keyCount = Object.keys(updateBody).length;
    let currentKeyIndex = 0;

    // updateBody.tbl will declare which table ot edit
    var sql = `
    UPDATE ${updateBody.tbl} SET `
    for (let key in updateBody) {
        // Loop through all items of a given table
        if (updateBody.hasOwnProperty(key)) {
            currentKeyIndex++;
            // Skips the table declaration
            if (key === 'tbl') {
                continue;
            }
            // Skips the emp_ID declaration
            if (key === 'emp_ID') {
                continue;
            }

            const value = updateBody[key];
            sql += `${key} = `

            if (typeof value === 'string') {
                sql += `'${value}'`
            } else if (typeof value === 'number' && Number.isInteger(value)) {
                sql += `${value}`
            }
            else if (!value) {
                sql += `null`
            }
            // Code to check if its the last value, if it is, then no comma
            if (currentKeyIndex < keyCount) {
                sql += ', ';
            }
        }
    }

    sql += ` WHERE emp_ID = ${req.body.emp_ID}`;

    console.log(sql)

    db.query(sql, function (error, result) {
        if (error) {
            console.log("Error:", error);
            if (error.code === 'ER_DUP_ENTRY' && error.errno === 1062) {
                // Handle duplicate entry error
                res.status(400).json({
                    error: "Duplicate entry error occurred",
                    code: error.code,
                    errno: error.errno
                });
            } else {
                // Handle other database errors
                res.status(500).send("Error Updating");
            }
        } else {
            console.log(`Updating of ${updateBody.tbl} Success`);
            res.json({ message: `Updating of ${updateBody.tbl} Success` });

        }
    });

})

// Update or Add Values, this one is relevant for one-to-many
app.put('/updateItem', verifyToken, (req, res) => {
    const updateBody = req.body;
    const table_primary_key = req.body.table_primary_key;


    // Code relevant to commas in sql query
    let keyCount = Object.keys(updateBody).length;
    let currentKeyIndex = 0;

    if (req.body.mode === 'edit') {
        // updateBody.tbl will declare which table to edit
        var sql = `UPDATE ${updateBody.tbl} SET `
        for (let key in updateBody) {
            // Loop through all items of a given table
            if (updateBody.hasOwnProperty(key)) {
                currentKeyIndex++;
                // Skips the declarations
                if (key === 'tbl' || key === 'item_ID' || key === 'mode' || key === 'table_primary_key') {
                    continue;
                }

                const value = updateBody[key];
                sql += `${key} = `

                if (typeof value === 'string') {
                    sql += `'${value}'`
                } else if (typeof value === 'number' && Number.isInteger(value)) {
                    sql += `${value}`
                }
                // Code to check if its the last value, if it is, then no comma
                if (currentKeyIndex < keyCount) {
                    sql += ', ';
                }
            }
        }
        sql += ` WHERE ${table_primary_key} = ${req.body.item_ID}`;
    }
    else if (req.body.mode === 'add') {
        var sql = `INSERT INTO ${updateBody.tbl} (`
        for (let key in updateBody) {
            currentKeyIndex++;
            // Skips declarations
            if (key === 'tbl' || key === 'item_ID' || key === 'table_primary_key' || key === 'mode') {
                continue;
            }
            sql += `${key}`
            if (currentKeyIndex < keyCount) {
                sql += ', ';
            }
        }
        currentKeyIndex = 0;
        sql += ') VALUES (';
        for (let key in updateBody) {
            currentKeyIndex++;
            // Skips declarations
            if (key === 'tbl' || key === 'item_ID' || key === 'table_primary_key' || key === 'mode') {
                continue;
            }
            const value = updateBody[key];
            sql += `'${value}'`
            if (currentKeyIndex < keyCount) {
                sql += ', ';
            }
        }
        sql += `)`
    }

    console.log(sql)

    db.query(sql, function (error, result) {
        if (error) {
            console.log("Error:", error);
            // Handle database errors
            res.status(500).send("Error Updating");
        } else {
            const cert_ID = result.insertId;
            console.log(`Updating of ${updateBody.tbl} Success`);
            res.json({
                message: `Updating of ${updateBody.tbl} Success`,
                cert_ID: cert_ID
            });
        }
    });

})

// Delete Values
app.put('/delete', verifyToken, (req, res) => {
    const updateBody = req.body;

    // Code relevant to commas in sql query
    let keyCount = Object.keys(updateBody).length;
    let currentKeyIndex = 0;

    // updateBody.tbl will declare which table ot edit
    var sql = `
    UPDATE ${updateBody.tbl} SET `
    for (let key in updateBody) {
        // Loop through all items of a given table
        if (updateBody.hasOwnProperty(key)) {
            currentKeyIndex++;
            // Skips the table declaration
            if (key === 'tbl') {
                continue;
            }
            // Skips the emp_ID declaration
            if (key === 'emp_ID') {
                continue;
            }
            const value = updateBody[key];
            sql += `${key} = NULL`
            // Code to check if its the last value, if it is, then no comma
            if (currentKeyIndex < keyCount) {
                sql += ', ';
            }

        }
    }

    sql += ` WHERE emp_ID = ${req.body.emp_ID}`;

    console.log(sql)

    db.query(sql, function (error, result) {
        if (error) {
            console.log("Error:", error);
            // Handle database errors
            res.status(500).send("Error Deleting");
        } else {
            console.log(`Deleting of ${updateBody.tbl} Success`);
            res.json({ message: `Deleting of ${updateBody.tbl} Success` });

        }
    });

})

// Delete Item
// This code is used for deleting an individual item of an array aka loopable component
app.post('/deleteItem', verifyToken, (req, res) => {
    const item_ID = req.body.item_ID;
    const table_primary_key = req.body.table_primary_key;
    const updateBody = req.body;

    sql = `DELETE FROM ${updateBody.tbl} WHERE ${table_primary_key} = ${item_ID}`;

    console.log(sql)

    db.query(sql, function (error, result) {
        if (error) {
            console.log("Error:", error);
            // Handle database errors
            res.status(500).send("Error Deleting");
        } else {
            console.log(`Deleting of ${updateBody.tbl} Success`);
            res.json({ message: `Deleting of ${updateBody.tbl} Success` });

        }
    });
})

// Uploading Certificate
const storage = multer.diskStorage({
    destination: 'uploads',
    filename: function (req, file, callback) {
        const extension = file.originalname.split('.').pop()
        callback(null, `${file.fieldname}-${Date.now()}.${extension}`)
    }
})

const upload = multer({ storage: storage }).single('file'); // Change to single file upload
const imgUpload = multer({ dest: 'uploads/' });

// Uploading files to Google Drive
app.post('/upload', async (req, res, next) => {
    try {
        upload(req, res, async function (err) {
            if (err instanceof multer.MulterError) {
                // A Multer error occurred when uploading.
                console.log(err);
                return res.status(500).json({ error: 'Multer error' });
            } else if (err) {
                // An unknown error occurred when uploading.
                console.log(err);
                return res.status(500).json({ error: 'Unknown error' });
            }

            const file = req.file;

            const auth = new google.auth.GoogleAuth({
                keyFile: "key.json",
                scopes: ['https://www.googleapis.com/auth/drive']
            })

            const drive = google.drive({ version: "v3", auth });

            const uploadedFiles = [];
            // Upload the files
            const response = await drive.files.create({
                requestBody: {
                    name: file.originalname,
                    mimeType: file.mimeType,
                    parents: ['1eM6sAWilyG29A12mDeb-gV1qbQpj0Opv']
                },
                media: { body: fs.createReadStream(file.path) }
            });

            uploadedFiles.push(response.data);

            // Retreieve the fileID from the newly uploaded file
            const fileID = response.data.id;

            // Get the download link using the above fileID
            const fileMetadata = await drive.files.get({
                fileId: fileID,
                fields: 'webViewLink'
            });
            const downloadLink = fileMetadata.data.webViewLink;


            res.json({
                downloadLink: downloadLink,
                fileID: fileID
            });
        });
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Upload profile picture
app.post('/upload_ProfilePicture', imgUpload.single('image'), (req, res) => {
    // Access uploaded file via req.file
    const image = req.file;
    const emp_ID = req.body.emp_ID;

    if (!image) {
        res.status(400).send('No file uploaded');
        return;
    }

    // Read the image data from the file
    const imageData = fs.readFileSync(image.path);

    // Update the image data for the specified employee ID
    const sql = 'UPDATE tbl_info SET profilePicture = ? WHERE emp_ID = ?';
    db.query(sql, [imageData, emp_ID], (error, results) => {
        if (error) {
            console.error('Error updating image data:', error);
            res.status(500).send('Error updating image data');
            return;
        }
        console.log('Image data updated for employee ID:', emp_ID);
        res.status(200).json({ message: 'Image data updated successfully' });

    });
});



// Deleting files from Google Drive
app.post('/deleteCertification', verifyToken, async (req, res) => {
    try {
        const fileId = req.body.attachment_ID; // Assuming fileId is sent in the request body
        console.log(`file ID to delete: ${fileId}`);

        if (!fileId) {
            return res.status(400).json({ error: 'File ID is required' });
        }

        const auth = new google.auth.GoogleAuth({
            keyFile: "key.json",
            scopes: ['https://www.googleapis.com/auth/drive']
        })

        const drive = google.drive({ version: "v3", auth });

        // Delete the file
        await drive.files.delete({
            fileId: fileId
        });

        res.json({
            message: 'File deleted successfully'
        });
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/createUser', verifyToken, (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const role = req.body.role;
    const department = req.body.department;

    const list_of_tables = [
        "tbl_accounting_details",
        "tbl_certification",
        "tbl_details",
        "tbl_education",
        "tbl_emergency",
        "tbl_personal_contact"
    ];

    let emp_ID = 0;

    // Check first if username already exists
    const sql_UsernameExistsCheck = `
        SELECT username
        FROM tbl_login
        WHERE username = "${username}"
    `
    db.query(sql_UsernameExistsCheck, function (error, result) {
        if (error) {
            console.log("Error:", error);
            return res.status(500).json({ error: "An error occurred while creating user." });
        } else {
            if (result.length > 0) {
                return res.status(200).json({
                    userExists: true,
                    message: "Username already exists."
                });
            }
            else if (result.length === 0) {
                bcrypt.hash(password, saltRounds, function (err, hash) {
                    if (err) {
                        console.log("Error:", err);
                        return res.status(500).json({ error: "An error occurred while hashing password." });
                    }
                    // Insert into tbl_login
                    const sql_tbl_login = `INSERT INTO tbl_login (username, password) VALUES ("${username}", "${hash}")`;
                    db.query(sql_tbl_login, function (error, result) {
                        if (error) {
                            console.log("Error:", error);
                            return res.status(500).json({ error: "An error occurred while creating user." });
                        } else {
                            emp_ID = result.insertId; // Assuming emp_ID is auto-generated and you want to use it
                            console.log("emp_ID:", emp_ID);

                            // Insert into tbl_info
                            const sql_tbl_info = `INSERT INTO tbl_info (emp_ID, emp_name, role) VALUES (${emp_ID}, "${username}", "${role}")`;
                            db.query(sql_tbl_info, function (error, result) {
                                if (error) {
                                    console.log("Error:", error);
                                    return res.status(500).json({ error: "An error occurred while creating user." });
                                } else {
                                    // Insert into other tables
                                    for (const table of list_of_tables) {
                                        let sql_tbl = '';

                                        // Logic to check if the user is admin_Department. Will apply a department as such.
                                        if (table == "tbl_details") {
                                            sql_tbl = `INSERT INTO ${table} (emp_ID, department) VALUES (${emp_ID}, '${department}')`;
                                        }
                                        else {
                                            sql_tbl = `INSERT INTO ${table} (emp_ID) VALUES (${emp_ID})`;
                                        }


                                        console.log(sql_tbl)
                                        db.query(sql_tbl, function (error, result) {
                                            if (error) {
                                                console.log("Error:", error);
                                                return res.status(500).json({ error: "An error occurred while creating user." });
                                            }
                                        });
                                    }
                                    // Sending success response back to Angular app
                                    return res.status(200).json({ message: "User created successfully." });
                                }
                            });
                        }
                    });
                });
            }
        }
    });

});

app.post('/updateUser', verifyToken, (req, res) => {
    const emp_ID = req.body.emp_ID;
    const password = req.body.password;


    bcrypt.hash(password, saltRounds, function (err, hash) {
        if (err) {
            console.log("Error:", err);
            return res.status(500).json({ error: "An error occurred while hashing password." });
        }
        // Update username and password
        const sql_updateUser = `
                UPDATE tbl_login
                SET password = "${hash}"
                WHERE emp_ID = ${emp_ID}
                `;
        console.log(sql_updateUser);
        db.query(sql_updateUser, function (error, result) {
            if (error) {
                console.log("Error:", error);
                return res.status(500).json({ error: "An error occurred while updating user." });
            } else {
                return res.status(200).json({ message: "User updated successfully." });
            }
        });
    });

});

// Get already taken departments (for admin_Department purposes)
app.get('/getExistingDepAdmins', verifyToken, (req, res) => {
    const sql = ` SELECT d.department
            FROM tbl_details d
            INNER JOIN tbl_info i ON d.emp_ID = i.emp_ID
            WHERE i.role = 'admin_Department';
            `;

    db.query(sql, function (error, result) {
        if (error) {
            console.log("Error:", error);
            return res.status(500).json({ error: "An error occurred while getting departments." });
        } else {
            const departments = result.map(row => row.department); // Extracting only department names
            res.send(departments);
        }
    });
})

app.post('/deleteUser', verifyToken, (req, res) => {
    const emp_ID = req.body.emp_ID;
    const list_of_tables = [
        "tbl_accounting_details",
        "tbl_certification",
        "tbl_dependencies",
        "tbl_details",
        "tbl_education",
        "tbl_emergency",
        "tbl_experience",
        "tbl_info",
        "tbl_login",
        "tbl_org",
        "tbl_personal_contact",
        "tbl_provincial_contact",
        "tbl_skills",
        "tbl_teaching_loads",
    ];

    var tableNum = 0;

    list_of_tables.forEach(function (table) {
        tableNum += 1;
        sql = `DELETE FROM ${table} WHERE emp_ID = ${emp_ID};`
        console.log(sql);

        db.query(sql);

        if (tableNum === list_of_tables.length) {
            // Send the resultData object as a JSON response
            console.log(`${table}. reached the end, ending...`)
            return res.status(200).json({ message: "User deleted." });
        }
    })
});

app.listen(port, () => {
    console.log(`Server is running on profilingdatabase.c70w002qw0l1.us-east-1.rds.amazonaws.com:${port}`);
});
