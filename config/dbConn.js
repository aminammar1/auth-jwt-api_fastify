const { MongoClient } = require("mongodb");

let client = null;

const connectDB = async () => {
  try {
    const uri = process.env.DATABASE_URI;
    client = new MongoClient(uri, {});

    await client.connect();
    console.log("MongoDB Connected");
  } catch (error) {
    console.error("MongoDB Connection Error:", error);
    throw error;
  }
};

const getClient = () => {
  if (!client) {
    throw new Error("MongoDB client is not initialized");
  }
  return client;
};

module.exports = { connectDB, getClient };
