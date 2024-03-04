const fastifyJwt = require("@fastify/jwt");

const verifyJWT = async (fastify, options) => {
  fastify.register(fastifyJwt, {
    secret: process.env.ACCESS_TOKEN_SECRET,
  });

  fastify.addHook("preHandler", async (request, reply) => {
    try {
      await request.jwtVerify();
    } catch (error) {
      reply.status(401).send({ message: "Unauthorized" });
    }
  });
};

module.exports = verifyJWT;
