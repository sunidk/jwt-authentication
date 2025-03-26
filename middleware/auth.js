const jwt = require("jsonwebtoken");
const secretKey = process.env.JWT_SECRET_KEY;

const auth = (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).send("Access Denied: No token provided");
  }

  try {
    const decoded = jwt.verify(token, secretKey);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(400).send("Invalid Token");
  }
};

module.exports = auth;
