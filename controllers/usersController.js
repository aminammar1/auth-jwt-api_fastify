const { getClient } = require("../config/dbconn");

const getAllUsers = async (req, res) => {
  const db = getClient().db();
  const users = db.collection("users");

  try {
    const usersData = await users
      .find({}, { projection: { password: 0 } })
      .toArray();
    if (!usersData.length) {
      return res.status(400).send({ message: "No users found" });
    }
    res.send(usersData);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).send({ message: "Internal Server Error" });
  }
};

module.exports = {
  getAllUsers,
};
