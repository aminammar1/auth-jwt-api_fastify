const authController = require("../controllers/authController");

async function authRoutes(fastify, options) {
  fastify.post("/auth/register", authController.register);
  fastify.post("/auth/login", authController.login);
  fastify.get("/auth/refresh", authController.refresh);
  fastify.post("/auth/logout", authController.logout);
  fastify.post("/auth/forgotPassword", authController.forgotPassword);
  fastify.post("/auth/resetPassword", authController.resetPassword);
}

module.exports = authRoutes;
