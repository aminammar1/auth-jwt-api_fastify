require("dotenv").config();
const fastify = require("fastify")();
const { connectDB } = require("./config/dbConn");
const cors = require("@fastify/cors");
const PORT = process.env.PORT || 4000;

connectDB()
  .then(() => {
    console.log("Connected to MongoDB");

    fastify.register(require("@fastify/cookie"));
    fastify.register(require("@fastify/cors"), { origin: "*" });

    fastify.register(require("./routes/root"));
    fastify.register(require("./routes/authRoutes"));
    fastify.register(require("./routes/userRoutes"));

    fastify.listen(PORT, (err) => {
      if (err) {
        console.error(err);
        process.exit(1);
      }
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Error connecting to MongoDB:", error);
    process.exit(1);
  });
