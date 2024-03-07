const { getClient } = require("../config/dbConn");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const register = async (req, res) => {
  const { first_name, last_name, email, password } = req.body;
  if (!first_name || !last_name || !email || !password) {
    return res.status(400).send({ message: "All fields are required" });
  }

  const client = getClient();
  const users = client.db().collection("users");

  try {
    const foundUser = await users.findOne({ email: email });
    if (foundUser) {
      return res.status(401).send({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    console.log("Hashed Password:", hashedPassword);

    const newUser = {
      first_name,
      last_name,
      email: email,
      password: hashedPassword,
      createdAt: new Date(),
      updateAt: new Date(),
    };
    console.log("New User:", newUser);
    
    const result = await users.insertOne(newUser);
    
    console.log("Insert Result:", result);

    const insertedUser = result.ops[0];

    const accessToken = jwt.sign(
      {
        UserInfo: {
          id: insertedUser._id.toString(),
        },
      },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "15m" }
    );

    const refreshToken = jwt.sign(
      {
        UserInfo: {
          id: insertedUser._id.toString(),
        },
      },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("jwt", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(201).send({
      accessToken,
      email: insertedUser.email,
      first_name: insertedUser.first_name,
      last_name: insertedUser.last_name,
    });
  } catch (error) {
    console.error("Error:", error);
    res
      .status(500)
      .send({ message: "User registration failed: " + error.message });
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send({ message: "All fields are required" });
  }

  const client = getClient();
  const users = client.db().collection("users");

  try {
    const foundUser = await users.findOne({ email });
    if (!foundUser) {
      return res.status(401).send({ message: "User does not exist" });
    }

    const match = await bcrypt.compare(password, foundUser.password);
    if (!match) {
      return res.status(401).send({ message: "Wrong Password" });
    }

    const accessToken = jwt.sign(
      {
        UserInfo: {
          id: foundUser._id,
        },
      },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "15m" }
    );

    const refreshToken = jwt.sign(
      {
        UserInfo: {
          id: foundUser._id,
        },
      },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("jwt", refreshToken, {
      httpOnly: true, //accessible only by web server
      secure: true, //https
      sameSite: "None", //cross-site cookie
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.send({
      message: "success login",
      accessToken,
      email: foundUser.email,
    });
  } catch (error) {
    console.error("Error logging in user:", error);
    res.status(500).send({ message: "Internal Server Error" });
  }
};

const refresh = async (req, res) => {
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.status(401).send({ message: "Unauthorized" });

  const refreshToken = cookies.jwt;
  jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET,
    async (err, decoded) => {
      if (err) return res.status(403).send({ message: "Forbidden" });

      const client = getClient();
      const users = client.db().collection("users");

      try {
        const foundUser = await users.findOne({ _id: decoded.UserInfo.id });
        if (!foundUser) {
          return res.status(401).send({ message: "Unauthorized" });
        }

        const accessToken = jwt.sign(
          {
            UserInfo: {
              id: foundUser._id,
            },
          },
          process.env.ACCESS_TOKEN_SECRET,
          { expiresIn: "15m" }
        );

        res.send({ accessToken });
      } catch (error) {
        console.error("Error refreshing token:", error);
        res.status(500).send({ message: "Internal Server Error" });
      }
    }
  );
};

const logout = (req, res) => {
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.sendStatus(204);

  res.clearCookie("jwt", {
    httpOnly: true,
    sameSite: "None",
    secure: true,
  });

  res.send({ message: "success log out from the account ! " });
};

const generateRandomCode = () => {
  return Math.floor(100000 + Math.random() * 900000);
};

const forgotPassword = async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res
      .status(400)
      .send({ message: "Email is required for password reset" });
  }

  const client = getClient();
  const users = client.db().collection("users");

  try {
    const foundUser = await users.findOne({ email });

    if (!foundUser) {
      return res
        .status(404)
        .send({ message: "User not found with the provided email" });
    }

    const resetCode = generateRandomCode();
    const hashedCode = await bcrypt.hash(resetCode.toString(), 10);

    foundUser.resetPasswordCode = hashedCode;
    foundUser.resetPasswordExpires = Date.now() + 3600000;

    await users.updateOne({ email }, { $set: foundUser });

    res.send({
      message:
        "Reset code generated successfully. Use this code to reset your password.",
      resetCode,
    });
  } catch (error) {
    console.error("Error generating reset code:", error);
    res.status(500).send({ message: "Internal Server Error" });
  }
};

const resetPassword = async (req, res) => {
  const { email, resetCode, newPassword } = req.body;

  if (!email || !resetCode || !newPassword) {
    return res.status(400).send({
      message:
        "Email, resetCode, and newPassword are required for password reset",
    });
  }

  const client = getClient();
  const users = client.db().collection("users");

  try {
    const foundUser = await users.findOne({ email });

    if (!foundUser) {
      return res
        .status(404)
        .send({ message: "User not found with the provided email" });
    }

    const isValidCode = await bcrypt.compare(
      resetCode.toString(),
      foundUser.resetPasswordCode
    );

    if (!isValidCode || Date.now() > foundUser.resetPasswordExpires) {
      return res.status(401).send({ message: "Invalid or expired reset code" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    foundUser.password = hashedPassword;

    await users.updateOne(
      { email },
      {
        $set: { password: hashedPassword },
        $unset: { resetPasswordCode: "", resetPasswordExpires: "" },
      }
    );

    res.send({ message: "Password reset successful" });
  } catch (error) {
    console.error("Error resetting password:", error);
    res.status(500).send({ message: "Internal Server Error" });
  }
};

module.exports = {
  register,
  login,
  refresh,
  logout,
  forgotPassword,
  resetPassword,
};
