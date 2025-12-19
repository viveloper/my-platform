import Fastify from "fastify";

async function startBackend() {
  const fastify = Fastify({ logger: true });

  // 모든 요청에 대해 JWT 검사 (Middleware 시뮬레이션)
  fastify.addHook("onRequest", async (request, reply) => {
    const authHeader = request.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      reply
        .code(401)
        .send({ error: "🚨 [Backend] Access Token이 없습니다! 접근 불가." });
      return;
    }

    // 실제로는 여기서 JWT 서명을 검증하지만, 지금은 토큰 내용만 로그로 확인
    const token = authHeader.split(" ")[1];
    request.userToken = token;

    console.log(`✅ [Backend] JWT 수신 성공! (길이: ${token.length})`);
  });

  // 보호된 API 엔드포인트
  fastify.get("/orders", async (request, reply) => {
    return {
      data: ["Order #1", "Order #2"],
      message: "이 데이터는 오직 JWT를 가진 BFF만 볼 수 있습니다.",
      receivedBy: "Resource Server (Port 4000)",
    };
  });

  try {
    await fastify.listen({ port: 4000 });
    console.log(
      "🛡️  Resource Server (Backend) running at http://localhost:4000",
    );
  } catch (err) {
    process.exit(1);
  }
}

startBackend();
