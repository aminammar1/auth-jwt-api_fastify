const authController = require("../controllers/authController");

async function authRoutes(fastify, options) {
  fastify.post("/auth/register", authController.register);
  fastify.post("/auth/login", authController.login);
  fastify.get("/auth/refresh", authController.refresh);
  fastify.post("/auth/logout", authController.logout);
}

module.exports = authRoutes;
