import Fastify from "fastify";
import fastifyCookie from "@fastify/cookie"; // 1. 쿠키 플러그인 import
import {
  buildAuthorizationUrl,
  authorizationCodeGrant,
  fetchUserInfo,
  allowInsecureRequests,
} from "openid-client";
import { getOIDCConfig, REDIRECT_URI } from "./config.js";
import crypto from "node:crypto"; // Session ID 생성을 위해 사용

// [추가] JWT 파싱 유틸
function parseJwt(token) {
  try {
    return JSON.parse(Buffer.from(token.split(".")[1], "base64").toString());
  } catch (e) {
    return {};
  }
}

// [핵심] In-Memory Session Store (실무에선 Redis로 대체될 부분)
// 구조: Map<sessionId, { accessToken, refreshToken, userInfo }>
const sessionStore = new Map();

async function startServer() {
  const fastify = Fastify({ logger: true });
  const oidcConfig = await getOIDCConfig();

  // 2. 쿠키 플러그인 등록
  // secret은 쿠키 서명(Signing)에 쓰입니다. 실무에선 환경변수로 관리!
  fastify.register(fastifyCookie, {
    secret: "super-secret-key-for-cookie-signing-must-be-long",
    hook: "onRequest",
  });

  fastify.get("/", async (request, reply) => {
    // 로그인 여부에 따라 다른 메시지 보여주기
    const sessionId = request.cookies.sessionId;
    if (sessionId && sessionStore.has(sessionId)) {
      return {
        status: "Logged In",
        message: "인증된 사용자입니다. /me 로 이동해서 정보를 확인하세요.",
      };
    }
    return {
      status: "Guest",
      message: "로그인이 필요합니다. /login 으로 이동하세요.",
    };
  });

  fastify.get("/login", async (request, reply) => {
    const authorizationUrl = buildAuthorizationUrl(oidcConfig, {
      redirect_uri: REDIRECT_URI,
      scope: "openid profile email", // refresh token 필요시 'offline_access' 추가
    });
    reply.redirect(authorizationUrl.href);
  });

  // [수정됨] Callback: 토큰 저장 -> 쿠키 설정 -> 리다이렉트
  fastify.get("/callback", async (request, reply) => {
    try {
      const currentUrl = new URL(request.url, "http://localhost:3000");
      const tokenSet = await authorizationCodeGrant(oidcConfig, currentUrl, {
        pkce: false,
      });

      const claims = parseJwt(tokenSet.id_token);
      const userClaims = await fetchUserInfo(
        oidcConfig,
        tokenSet.access_token,
        claims.sub,
      );

      // 1. Session ID 생성 (UUID)
      const sessionId = crypto.randomUUID();

      // 2. 서버 메모리에 토큰과 유저 정보 저장 (Redis 역할)
      sessionStore.set(sessionId, {
        accessToken: tokenSet.access_token,
        refreshToken: tokenSet.refresh_token, // 있다면 저장
        user: userClaims,
      });

      console.log(
        `💾 Session Created: ${sessionId} -> User: ${userClaims.preferred_username}`,
      );

      // 3. 브라우저에 쿠키 굽기 (Set-Cookie 헤더)
      // httpOnly: 자바스크립트 접근 불가 (XSS 방어)
      // path: 모든 경로에서 쿠키 전송
      reply.setCookie("sessionId", sessionId, {
        path: "/",
        httpOnly: true,
        secure: false, // 로컬 개발(http)이므로 false. 배포시 true 필수!
        sameSite: "lax",
        maxAge: 3600, // 1시간
      });

      // 4. 메인 페이지로 리다이렉트 (Location 헤더)
      return reply.redirect("/");
    } catch (err) {
      fastify.log.error(err);
      return { status: "Login Failed", error: err.message };
    }
  });

  // [추가] 내 정보 확인 (쿠키 검증 테스트용)
  fastify.get("/me", async (request, reply) => {
    // 1. 쿠키에서 Session ID 꺼내기
    const sessionId = request.cookies.sessionId;

    if (!sessionId) {
      return reply
        .code(401)
        .send({ error: "쿠키가 없습니다. 로그인해주세요." });
    }

    // 2. 저장소에서 매핑된 토큰/정보 찾기
    const session = sessionStore.get(sessionId);

    if (!session) {
      return reply
        .code(401)
        .send({ error: "세션이 만료되었거나 유효하지 않습니다." });
    }

    // 3. (중요) 프론트엔드에는 절대 Access Token을 주지 않고, 사용자 정보만 줍니다.
    return {
      message: "당신은 인증된 사용자입니다.",
      user: session.user,
      // accessToken: session.accessToken // <--- 이건 주석 해제하면 보안 사고입니다!
    };
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
