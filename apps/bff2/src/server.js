import Fastify from "fastify";
import fastifyCookie from "@fastify/cookie"; // 1. 쿠키 플러그인 import
import fastifyProxy from "@fastify/http-proxy";
import {
  buildAuthorizationUrl,
  authorizationCodeGrant,
  fetchUserInfo,
  refreshTokenGrant,
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

function isExpired(token) {
  try {
    const payload = parseJwt(token);
    // exp는 '초' 단위, Date.now()는 '밀리초' 단위
    const now = Math.floor(Date.now() / 1000);
    return payload.exp < now + 10; // 만료 10초 전이면 만료된 걸로 침
  } catch (e) {
    return true; // 파싱 안되면 만료된 셈 침
  }
}

async function startServer() {
  const fastify = Fastify({ logger: true });
  const oidcConfig = await getOIDCConfig();

  // 2. 쿠키 플러그인 등록
  // secret은 쿠키 서명(Signing)에 쓰입니다. 실무에선 환경변수로 관리!
  fastify.register(fastifyCookie, {
    secret: "super-secret-key-for-cookie-signing-must-be-long",
    hook: "onRequest",
  });

  // 3. Token Translation Proxy 설정 (핵심!)
  fastify.register(fastifyProxy, {
    upstream: "http://localhost:4000", // 백엔드 주소
    prefix: "/api", // /api 로 시작하는 요청은 여기로

    // 프록시 전에 실행될 로직 (토큰 주입)
    preHandler: async (request, reply) => {
      const sessionId = request.cookies.sessionId;

      // [시나리오 B] 쿠키 없음 -> 즉시 퇴장
      if (!sessionId || !sessionStore.has(sessionId)) {
        throw new Error("No Session");
      }

      const session = sessionStore.get(sessionId);

      // [시나리오 A] 토큰 만료 체크 & 갱신
      if (isExpired(session.accessToken)) {
        console.log("⚠️ Access Token 만료됨! Refresh 시도...");

        if (!session.refreshToken) {
          throw new Error("Refresh Token 없음. 재로그인 필요.");
        }

        try {
          // 1. Keycloak에 Refresh Token을 주고 새 토큰셋 받기
          const newTokenSet = await refreshTokenGrant(
            oidcConfig,
            session.refreshToken,
            {
              access_token: session.accessToken, // v6 일부 스펙 대응
            },
          );

          // 2. 세션 정보 업데이트
          session.accessToken = newTokenSet.access_token;
          // Refresh Token Rotation (새 리프레시 토큰이 오면 교체, 안 오면 기존 유지)
          if (newTokenSet.refresh_token) {
            session.refreshToken = newTokenSet.refresh_token;
          }

          sessionStore.set(sessionId, session); // 저장소 갱신
          console.log("♻️ Token Refresh 성공! (사용자는 모름)");
        } catch (refreshError) {
          console.error("❌ Refresh 실패 (완전 만료):", refreshError.message);
          sessionStore.delete(sessionId); // 세션 파기
          reply.clearCookie("sessionId");
          throw new Error("Session Expired");
        }
      }

      // 정상(또는 갱신된) 토큰 주입
      request.headers["authorization"] = `Bearer ${session.accessToken}`;
      delete request.headers["cookie"];
    },

    // 에러 처리
    errorHandler: (error, request, reply) => {
      reply
        .code(401)
        .send({ error: "Proxy Unauthorized", message: error.message });
    },
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
      const currentUrl = new URL(request.url, "http://localhost:3001");
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
    await fastify.listen({ port: 3001 });
    console.log("🚀 BFF Server running at http://localhost:3001");
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

startServer();
