import { allowInsecureRequests, discovery } from "openid-client";

// Keycloak 설정 상수
const KEYCLOAK_ISSUER = "http://localhost:8080/realms/my-platform";
const CLIENT_ID = "my-bff-client";
const CLIENT_SECRET = "LC4pn4KlZFURq7ZAivr6fsaEwE6h8X95"; // ★ 아까 메모한 Secret
export const REDIRECT_URI = "http://localhost:3000/callback";

let _config = null;

export async function getOIDCConfig() {
  if (_config) return _config;

  console.log(`🔍 Discovering Keycloak at ${KEYCLOAK_ISSUER}...`);

  // v6: discovery 함수는 서버 메타데이터를 받아와서 설정을 구성합니다.
  // 세 번째 인자가 client_secret 입니다.
  try {
    _config = await discovery(
      new URL(KEYCLOAK_ISSUER),
      CLIENT_ID,
      CLIENT_SECRET,
      undefined,
      {
        execute: [allowInsecureRequests],
      }
    );

    console.log("✅ Keycloak Discovery 성공! (v6 Config Loaded)");
    return _config;
  } catch (error) {
    console.error("❌ Keycloak 연결 실패:", error);
    process.exit(1);
  }
}
