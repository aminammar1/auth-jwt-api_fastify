const usersController = require("../controllers/usersController");
const verifyJWT = require("../middleware/verifyJWT");

async function userRoutes(fastify, options) {
  fastify.register(verifyJWT);

  fastify.get("/users", async (request, reply) => {
    return usersController.getAllUsers(request, reply);
  });
}

module.exports = userRoutes;
