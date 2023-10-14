const express = require("express");
const userdb = require("../models/userSchema");
const router = new express.Router();
const bcrypt = require('bcryptjs');
const authenticate = require("../middleware/authenticate");

/// for user rgistration 
router.post('/register', async (req, res) => {
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