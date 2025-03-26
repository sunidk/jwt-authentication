const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const secretKey = process.env.JWT_SECRET_KEY;
const db = require("../model/index");
const { STATUS_CODE } = require("../utils/constant");

exports.userRegister = async (req, res) => {
  try {
    const { userName, email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const usersRef = db.collection("users");
    const snapshot = await usersRef.where("userName", "==", userName).get();

    if (!snapshot.empty) {
      return res.status(400).send("User already exists");
    }

    const userRef = await usersRef.add({
      userName: userName,
      email: email,
      password: hashedPassword,
    });

    return res.send({
      status: STATUS_CODE.SUCCESS,
      message: "User Registered Successfully",
      userId: userRef.id,
    });
  } catch (error) {
    console.error("Error registering user:", error);
    return res.status(500).send("Error registering user");
  }
};

exports.userLogin = async (req, res) => {
  try {
    const { userName, password } = req.body;

    const userRef = db.collection("users").where("userName", "==", userName);
    const userSnapshot = await userRef.get();

    if (userSnapshot.empty) {
      return res.status(404).send("User not found");
    }

    const userDoc = userSnapshot.docs[0];
    const userData = userDoc.data();

    const validPassword = await bcrypt.compare(password, userData.password);

    if (!validPassword) {
      return res.status(401).send("Invalid credentials");
    }

    const token = jwt.sign({ userName: userData.userName }, secretKey, {
      expiresIn: "1h",
    });

    return res.send({
      status: STATUS_CODE.SUCCESS,
      message: "User Login Success",
      token,
    });
  } catch (error) {
    console.error("Error logging in user:", error);
    return res.status(500).send("Error logging in user");
  }
};

exports.healthcheck = async (req, res) => {
  try {
    return res.send({
      status: STATUS_CODE.SUCCESS,
      message: "Health check completed",
    });
  } catch (error) {
    console.error("Error logging in user:", error);
    return res.status(500).send("Error logging in user");
  }
};
