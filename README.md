## 🛡️ AuthServer - Spring Boot 기반 인증 서버

`AuthServer`는 파이헬스케어에서 개발하는 여러 서비스의 인증 기능을 통합하기 위해 구축된 **중앙 인증 서버**입니다.  
Spring Boot 3, Spring Security 6 기반으로 구성되었으며, **JWT 기반의 Stateless 인증/인가**,  
일반 회원가입/로그인, **OAuth2 기반 소셜 로그인(Naver, Google)** 기능을 제공합니다.

### 🔐 주요 기능
- JWT 기반 Access / Refresh Token 인증 및 재발급
- 이메일·비밀번호 기반 일반 로그인
- Naver, Google OAuth2 소셜 로그인
- 사용자 이름 중복 확인 및 예외 핸들링
- Spring Security 커스터마이징 및 필터 체인 구성
- HTTP Header를 통한 토큰 전달 방식
- 클라이언트-서버 간 인증 사양 표준화

### 📁 주요 패키지 구조
- `auth.credentials` - 일반 로그인 관련 로직 (Controller, Service, DTO 등)
- `auth.oauth2` - OAuth2 소셜 로그인 관련 서비스 및 사용자 정보 처리
- `jwt` - 토큰 생성, 필터, 인증/인가 처리
- `refresh` - RefreshToken 발급 및 재발급 로직
- `config` - Spring Security, RestTemplate 설정
- `exception` - 공통 에러 처리 및 예외 핸들러
- `controller` - HealthCheck 및 유저 컨트롤러

---

> 본 프로젝트는 단일 인증 서버를 통해 **다수의 앱/웹 서비스에서 일관된 로그인 처리**를 수행할 수 있도록 설계되었습니다.

