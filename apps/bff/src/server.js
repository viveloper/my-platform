import Fastify from "fastify";
import {
  buildAuthorizationUrl,
  authorizationCodeGrant,
  fetchUserInfo,
} from "openid-client";
import { getOIDCConfig, REDIRECT_URI } from "./config.js";

// [추가] JWT 토큰의 Payload(내용물)를 열어보는 유틸리티 함수
// 외부 라이브러리 없이 Node.js Buffer로 간단히 구현 가능합니다.
function parseJwt(token) {
  try {
    return JSON.parse(Buffer.from(token.split(".")[1], "base64").toString());
  } catch (e) {
    console.error("JWT Parsing failed:", e);
    return {};
  }
}

async function startServer() {
  const fastify = Fastify({ logger: true });
  const oidcConfig = await getOIDCConfig();

  fastify.get("/", async (request, reply) => {
    return { hello: "BFF Gateway", status: "Secure" };
  });

  fastify.get("/login", async (request, reply) => {
    const authorizationUrl = buildAuthorizationUrl(oidcConfig, {
      redirect_uri: REDIRECT_URI,
      scope: "openid profile email",
    });
    reply.redirect(authorizationUrl.href);
  });

  fastify.get("/callback", async (request, reply) => {
    try {
      const currentUrl = new URL(request.url, "http://localhost:3000");

      // 1. Token 교환
      const tokenSet = await authorizationCodeGrant(oidcConfig, currentUrl, {
        pkce: false,
      });

      console.log("🔑 Token Exchange Success!");

      // [수정] ID Token을 파싱하여 'sub' (사용자 고유 ID) 추출
      const claims = parseJwt(tokenSet.id_token);
      console.log("📜 ID Token Claims:", claims);

      // 2. User Info 가져오기 (교차 검증 수행)
      // "내가 AccessToken으로 조회하려는 정보가, ID Token에 적힌 이 사람(claims.sub) 것이 맞느냐?"
      const userClaims = await fetchUserInfo(
        oidcConfig,
        tokenSet.access_token,
        claims.sub, // ★ 필수: 추출한 sub 값을 검증용으로 전달
      );

      console.log("🆔 User Info Verified:", userClaims);

      return {
        status: "Authentication Successful",
        user: userClaims.preferred_username,
        email: userClaims.email,
        sub: claims.sub,
      };
    } catch (err) {
      fastify.log.error(err);
      return {
        status: "Login Failed",
        error: err.message,
      };
    }
  });

  try {
    await fastify.listen({ port: 3000 });
    console.log("🚀 BFF Server running at http://localhost:3000");
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

startServer();
