import express from "express"
import { MongoClient, UUID } from "mongodb"
import Cors from 'cors'
import * as dotenv from 'dotenv'
import nodemailer from 'nodemailer'
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcrypt';
// var crypto = require('crypto')
dotenv.config()
const router = express.Router()
uuidv4();
const app = express()
const PORT = 8000

//Inbuilt middleware =>  say data is in json => converting body to json
app.use(express.json())
app.use(Cors())

const MONGO_URL = process.env.MONGO_URL

async function createConnection() {
    const client = new MongoClient(MONGO_URL);
    await client.connect()
    console.log("Mongodb is connected")
    return client
}


const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});



export const client = await createConnection()

// app.use("/details", productsRouter)
async function insertALLDetails(query) {
    return await client.db("B53-node").collection("details").insertOne(query)
}



app.post('/register', async (req, res) => {
    const details = req.body;

    try {
        // Hash the password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(details.password, saltRounds);

        // Replace the plain text password with the hashed password
        details.password = hashedPassword;

        // Insert the user details into the database
        const result = await insertALLDetails(details);
        res.send(result);
    } catch (error) {
        console.error('Error during registration:', error.message);
        res.status(500).send('Registration failed');
    }

})

// Login Endpoint
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await client.db("B53-node").collection("details").findOne({ email });
        if (!user) return res.status(404).send('User not found');

        // Compare the password with the hashed password stored in the database
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).send('Invalid credentials');

        // Generate a token or session here for the authenticated user
        res.status(200).send('Login successful');
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Assuming you have an Express.js server
app.get('/users', async (req, res) => {
    try {
        const users = await client.db("B53-node").collection("details").find().toArray();
        res.status(200).json(users);
    } catch (error) {
        res.status(500).send('Error fetching user data');
    }
});


app.post('/reset', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await client.db("B53-node").collection("details").findOne({ email });
        if (!user) return res.status(404).send('User not found');

        const resetCode = Math.random().toString(36).substring(2, 8).toUpperCase();
        user.resetCode = resetCode;
        user.resetCodeExpiry = Date.now() + 3600000; // 1 hour expiry

        await client.db("B53-node").collection("details").updateOne({ email }, { $set: { resetCode: resetCode, resetCodeExpiry: user.resetCodeExpiry } });

        const mailOptions = {
            from: 'gokulraj482@gmail.com',
            to: user.email,
            subject: 'Password Reset Code',
            text: `Your password reset code is ${resetCode}`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log(error);
                return res.status(500).send('Error sending email');
            }
            res.status(200).send('Reset code sent to your email');
        });
    } catch (error) {
        res.status(500).send(error.message);
    }
});


app.post('/verify-code', async (req, res) => {
    const { email, code } = req.body;

    try {
        const user = await client.db("B53-node").collection("details").findOne({ email });
        if (!user) return res.status(404).send('User not found');

        if (user.resetCode !== code) {
            return res.status(400).send('Invalid or expired reset code');
        }

        if (Date.now() > user.resetCodeExpiry) {
            return res.status(400).send('Reset code has expired');
        }

        // Code is valid and not expired
        res.status(200).send('Code verified successfully');
    } catch (error) {
        res.status(500).send(error.message);
    }
});



// Change Password Endpoint
app.post('/change-password', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await client.db("B53-node").collection("details").findOne({ email });
        if (!user) return res.status(404).send('User not found');

        // Hash the password before storing it
        const hashedPassword = await bcrypt.hash(password, 10); // 10 is the salt rounds, you can adjust this

        await client.db("B53-node").collection("details").updateOne({ email }, { $set: { password: hashedPassword } });

        res.status(200).send('Password updated successfully');
    } catch (error) {
        res.status(500).send(error.message);
    }
});



app.listen(PORT, () => console.log(`Server started on the PORT, ${PORT}`))
