async function rootRoute(fastify, options) {
  fastify.get("/", async (request, reply) => {
    return "Hello in my API";
  });
}

module.exports = rootRoute; 
