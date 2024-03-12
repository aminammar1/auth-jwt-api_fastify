require("dotenv").config();
const fastify = require("fastify")();
const fastifyPassport = require("@fastify/passport");
const { connectDB } = require("./config/dbConn");
const cors = require("@fastify/cors");
const fastifySecureSession = require("@fastify/secure-session");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const PORT = process.env.PORT || 4000;

connectDB()
  .then(() => {
    console.log("Connected to MongoDB");

    const key = crypto.randomBytes(32);
    fs.writeFileSync(path.join(__dirname, "not-so-secret-key"), key);

    fastify.register(fastifySecureSession, {
      key: key,
      cookie: {
        path: "/",
      },
    });

    fastify.register(fastifyPassport.initialize());
    fastify.register(fastifyPassport.secureSession());

    fastifyPassport.use(
      "google",
      new GoogleStrategy(
        {
          clientID: process.env.GOOGLE_CLIENT_ID,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET,
          callbackURL: "http://localhost:4000/auth/google/callback",
        },
        function (accessToken, refreshToken, profile, cb) {
          cb(undefined, profile);
        }
      )
    );

    fastifyPassport.registerUserDeserializer(async (user, req) => {
      return user;
    });

    fastifyPassport.registerUserSerializer(async (user, req) => {
      return user;
    });

    fastify.get(
      "/auth/google/callback",
      {
        preValidation: fastifyPassport.authenticate("google", {
          scope: ["profile"],
        }),
      },
      async (req, res) => {
        res.redirect("/");
      }
    );

    fastify.get(
      "/login",
      fastifyPassport.authenticate("google", { scope: ["profile"] })
    );

    fastify.get("/logout", async (req, res) => {
      req.logout();
      return { success: true };
    });

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
