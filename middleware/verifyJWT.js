const jwt = require("jsonwebtoken");

const verifyJWT = async (fastify, options) => {
  fastify.addHook("preHandler", async (request, reply) => {
    const token =
      request.headers.authorization &&
      request.headers.authorization.split(" ")[1];
    if (!token) {
      reply.status(401).send({ message: "Unauthorized" });
      return;
    }
    try {
      const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
      request.user = decoded; 
    } catch (error) {
      reply.status(401).send({ message: "Unauthorized" });
    }
  });
};

module.exports = verifyJWT;
