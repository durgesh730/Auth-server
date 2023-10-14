const express = require("express");
const userdb = require("../models/userSchema");
const router = new express.Router();
const bcrypt = require('bcryptjs');
const authenticate = require("../middleware/authenticate");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken")


const keysecret = "durgeshchaudharydurgeshchaudhary";

// email config
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: "durgeshchaudhary020401@gmail.com",
        pass: "lqfxwpogsaocehjc"
    }
})


/// for user rgistration 

router.post('/register', async (req, res) => {
    // console.log(req.body);

    const { fname, email, password, cpassword } = req.body;

    if (!fname || !email || !password || !cpassword) {
        res.status(404).json({ error: "fill all the deatils" })
    }
    try {
        const preuser = await userdb.findOne({ email: email });
        if (preuser) {
            res.status(404).json({ error: "This Email is Already Exist" });
        } else if (password !== cpassword) {
            res.status(404).json({ error: "This Email is Already Exist" });
        } else {
            const finalUser = new userdb({
                fname, email, password, cpassword
            });

            // here password hashing
            const storeData = await finalUser.save();
            //  console.log(storeData);
            res.status(201).json({ status: 201, storeData })
        }

    } catch (error) {
        res.status(404).json({ error });
        console.log("catch block error");
    }
})

// user Login
router.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(422).json({ error: "Please fill in all the details" });
    }

    try {
        const user = await userdb.findOne({ email: email });

        if (!user) {
            // User with the provided email not found
            return res.status(404).json({ error: "User not found" });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            // Password doesn't match
            return res.status(401).json({ error: "Invalid password" });
        }

        // Password matches, generate token
        const token = await user.generateAuthtoken();

        // Set the usercookie as an HTTP-only cookie
        res.cookie("usercookie", token, {
            expires: new Date(Date.now() + 9000000),
            httpOnly: true
        });

        // Respond with user and token
        const result = {
            user,
            token,
            msg: "Logged In Successfully"
        };
        return res.status(200).json(result);
    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: "Server error" });
    }
});




// user valid
router.get("/validuser", authenticate, async (req, res) => {
    try {
        const ValidUserOne = await userdb.findOne({ _id: req.userId });
        res.status(201).json({ status: 201, ValidUserOne });
    } catch (error) {
        res.status(401).json({ status: 401, error });
    }
});

// send email link for reset password

router.post("/sendpasswordlink", async (req, res) => {
    const { email } = req.body;

    if (!email) {
        res.status(401).json({ status: 401, message: "Enter Your Email" })
    }

    try {
        const userfind = await userdb.findOne({ email: email });

        // token generate for reset password
        const token = jwt.sign({ _id: userfind._id }, keysecret,
            {
                expiresIn: "1d"
            })
        const setusertoken = await userdb.findByIdAndUpdate({ _id: userfind._id }, { verifytoken: token }, { new: true })

        if (setusertoken) {
            const mailOptions = {
                from: "durgeshchaudhary020401@gmail.com",
                to: email,
                subject: "sending email of password Reset",
                text: `this link valid for 2 minutes http://localhost:3000/forgotpassword/${userfind.id}/${setusertoken.verifytoken}`
            }

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.log('error', error);
                    res.status(401).json({ status: 401, message: "email not send" })
                } else {
                    console.log("Email sent ", info.response);
                    res.status(201).json({ status: 201, message: "email send successfully" })
                }
            })
        }
    } catch (error) {
        res.status(201).json({ status: 201, message: "Invalid user" })
    }
})


// verify user for forgot password time

router.get("/forgotpassword/:id/:token", async (req, res) => {
    const { id, token } = req.params;
    try {
        const validuser = await userdb.findOne({ _id: id, verifytoken: token });

        // verify user token 
        const verifyToken = jwt.verify(token, keysecret);

        if (validuser && verifyToken._id) {
            res.status(201).json({ status: 201, validuser })
        } else {
            res.status(401).json({ status: 401, message: "user not exist" })
        }

    } catch (error) {
        res.status(401).json({ status: 401, error })
    }

});

// change password

router.post("/:id/:token", async (req, res) => {
    const { id, token } = req.params;
    const { password } = req.body;
    try {

        const validuser = await userdb.findOne({ _id: id, verifytoken: token });

        // verify user token 
        const verifyToken = jwt.verify(token, keysecret);

        if (validuser && verifyToken._id) {
            const newpassword = await bcrypt.hash(password, 12)

            // update user password
            const setnewuserpass = await userdb.findByIdAndUpdate({ _id: id }, { password: newpassword });

            setnewuserpass.save()  //save user
            res.status(201).json({ status: 201, setnewuserpass })

        } else {
            res.status(401).json({ status: 401, message: "user not exist" })
        }
    } catch (error) {
        res.status(401).json({ status: 401, error })
    }
})

router.put('/api/forms/:id', async (req, res) => {
    const id = req.params.id;
    const formData = req.body;
    try {
        // Update the document with the given ID
        const result = await userdb.findByIdAndUpdate(id, formData, {
            new: true, // Return the updated document
        });

        if (!result) {
            return res.status(404).json({ message: 'Form not found' });
        }

        res.status(200).json(result);
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

module.exports = router;