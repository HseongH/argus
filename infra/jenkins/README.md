# Argus 임시 스캔 서버 (Jenkins)

Argus 본체를 구현하기 전에 사용할 임시 구성입니다. Jenkins 잡 하나가 애플리케이션 소스를 스캔하고, 결과를 SARIF와 CycloneDX SBOM 파일로 호스트 디렉터리에 저장합니다.

## 구성

| 분석 | 도구 | 결과 파일 |
| --- | --- | --- |
| 시크릿 스캐닝 | Gitleaks | `gitleaks.sarif` (시크릿 원문은 `REDACTED`로 마스킹) |
| 의존성 취약점(CVE) | Trivy | `trivy.sarif` |
| 보안 취약 패턴 | Semgrep (`p/java`) | `semgrep.sarif` |
| 버그 패턴 | PMD (`quickstart` 규칙) | `pmd.sarif` |
| 의존성 목록 + EOL | Trivy + endoflife.date | `sbom.cdx.json` (`argus:eol:*` 속성) |
| 실행 정보 | - | `manifest.json` (도구 버전, 단계별 성공 여부, 소스 커밋) |

결과는 `reports/<APP_NAME>/<YYYYMMDD-HHMMSS>/`에 저장되며, `reports/<APP_NAME>/latest`가 가장 최근 결과를 가리킵니다.

모든 스캐너는 Jenkins 컨테이너 하나에 설치되어 있으므로, 컨테이너 안에서 다른 컨테이너를 실행하지 않습니다.

## 실행

### 1. 환경 파일 준비

```bash
cp .env.example .env
```

`.env`에서 `JENKINS_ADMIN_PASSWORD`를 설정합니다. 사내 Nexus 같은 Maven 미러가 있으면 `MAVEN_MIRROR_URL`도 설정합니다.

### 2. 기동

Podman(rootless):

```bash
podman compose -f compose.yaml -f compose.podman.yaml up -d --build
```

Docker:

```bash
docker compose up -d --build
```

첫 빌드는 JDK 8/17, Semgrep, PMD를 내려받으므로 몇 분 정도 걸립니다. 기동 후 <http://localhost:8080>에 `admin` 계정으로 로그인할 수 있습니다.

### 3. 스캔 실행

Jenkins 화면에서 `argus-scan` 잡의 **Build with Parameters**를 실행하거나, 호스트에서 스크립트를 실행합니다.

원격 저장소:

```bash
./trigger-scan.sh my-app git https://github.com/org/my-app.git main
```

비공개 저장소는 먼저 Jenkins에서 **Manage Jenkins > Credentials**에 `Username with password` 자격 증명을 만들고(비밀번호 칸에 토큰 입력), 그 ID를 다섯 번째 인자로 넘깁니다.

```bash
./trigger-scan.sh my-app git https://github.com/org/my-app.git main my-git-token
```

로컬 소스는 `sources/` 아래에 복사하거나 `.env`의 `SOURCES_DIR`을 소스 디렉터리로 지정한 뒤 상대 경로로 실행합니다. 원본은 읽기 전용으로 마운트되며, 스캔은 복사본에서 진행됩니다.

```bash
./trigger-scan.sh my-app local my-app
```

## 잡 파라미터

| 파라미터 | 설명 |
| --- | --- |
| `APP_NAME` | 결과 폴더 이름입니다. 영문, 숫자, `.`, `_`, `-`만 사용할 수 있습니다. |
| `SOURCE_TYPE` | `git` 또는 `local` |
| `GIT_URL`, `GIT_REF` | clone할 주소와 브랜치/태그입니다. `GIT_REF`가 비어 있으면 기본 브랜치를 사용합니다. |
| `GIT_CREDENTIALS_ID` | 비공개 저장소용 자격 증명 ID입니다. 토큰은 URL이나 로그에 남지 않습니다. |
| `LOCAL_PATH` | `sources/` 기준 상대 경로입니다. |
| `BUILD_JDK` | 의존성을 해석할 때 사용할 JDK입니다. `auto`는 Gradle 7.3 미만이면 8, 그 이상이면 17을 사용합니다. |

## 빌드 도구별 지원 범위

스캔은 프로젝트를 컴파일하지 않고, 의존성 목록만 해석합니다. Gitleaks, Semgrep, PMD는 소스 파일만 읽으므로 빌드 도구와 관계없이 동작합니다.

| 빌드 도구 | 의존성 해석 방법 | 제약 |
| --- | --- | --- |
| Gradle | init script로 의존성 잠금을 켜고 `./gradlew`로 `gradle.lockfile`을 생성한 뒤 Trivy가 읽습니다. | `gradlew`가 있어야 합니다. Gradle 6 이하는 잠금 파일 형식이 달라 CVE 결과가 비어 있을 수 있습니다. |
| Maven | `./mvnw` 또는 `mvn`으로 의존성을 `~/.m2`에 내려받은 뒤 Trivy가 `pom.xml`을 읽습니다. | 사내 parent POM이나 사내 저장소를 쓰면 `MAVEN_MIRROR_URL`이 필요합니다. |
| Ant 등 그 밖의 프로젝트 | Gradle/Maven 빌드 파일이 없으면 Trivy를 `rootfs` 모드로 실행해서 소스 트리 안의 jar 파일(`lib/*.jar` 등)을 직접 식별합니다. | 저장소에 jar가 포함되어 있어야 합니다. Ivy(`ivy.xml`)로 받는 의존성은 해석하지 않습니다. |

Gradle과 Maven의 의존성 해석 과정에서 **프로젝트의 빌드 스크립트가 실행**되므로, 신뢰할 수 있는 저장소만 스캔해야 합니다. 사내 저장소 인증이 필요한 프로젝트는 의존성 해석에 실패할 수 있습니다.

## 동작 방식과 제약

- **Maven Central 요청 제한**: Maven Central은 짧은 시간에 요청이 많으면 IP를 약 30분간 차단합니다(HTTP 429). 여러 프로젝트를 연속으로 스캔할 때는 `MAVEN_MIRROR_URL`로 사내 미러를 지정하는 편이 안전합니다. 의존성 캐시는 `jenkins_home` 볼륨에 유지됩니다.
- **네트워크**: Trivy 취약점 DB(mirror.gcr.io), Semgrep 규칙(semgrep.dev), EOL 정보(endoflife.date)에 접근해야 합니다. 사내 프록시 환경이라면 컨테이너에 `HTTP_PROXY`/`HTTPS_PROXY`를 추가해야 합니다.
- **EOL 판정 범위**: Spring Boot, Spring Framework, Spring Security, Hibernate ORM, Tomcat, Jetty, Log4j, Struts, Kotlin, Quarkus 라이브러리와 Java 버전, Gradle/Maven wrapper 버전을 판정합니다. Java 지원 기간은 Eclipse Temurin을 기준으로 합니다. 목록은 `argus/eol_enrich.py`의 `MAVEN_PRODUCTS`에서 추가할 수 있습니다.
- **PMD**: 프레임워크 어노테이션이 붙은 클래스의 private 필드나 `unused`/`ignored`라는 이름의 변수처럼 관례상 의도된 코드는 보고하지 않습니다.
- **잡 정의**: `argus/` 디렉터리는 컨테이너의 `/opt/argus`에 마운트됩니다. `scan.sh`는 수정 즉시 반영되고, `Jenkinsfile`을 수정했을 때는 컨테이너를 재시작해야 반영됩니다.
- **결과 파일 소유자**: Podman은 `compose.podman.yaml`의 `keep-id` 설정으로, Docker는 호스트 사용자 uid가 1000일 때 결과 파일이 현재 사용자 소유로 생성됩니다.

## 버전 고정

이미지를 언제 다시 빌드해도 같은 구성이 나오도록 모든 구성 요소의 버전을 고정했습니다.

| 대상 | 위치 | 검증 |
| --- | --- | --- |
| Jenkins, Gitleaks, Trivy, PMD, Maven, JDK 8/17 | `image/Containerfile`의 `ARG` | 배포처의 체크섬 파일 또는 고정된 SHA-256/SHA-512 |
| Semgrep과 하위 Python 패키지 | `image/semgrep-requirements.txt` | 정상 동작한 설치본의 `pip freeze` |
| Jenkins 플러그인(하위 의존성 포함 58개) | `image/plugins.txt` | 정상 동작한 Jenkins에서 추출한 버전 |

PMD는 체크섬 파일을 배포하지 않으므로, 고정할 때 내려받은 파일의 SHA-256을 기록했습니다. 버전을 올릴 때는 해당 값을 함께 바꾸고, 이미지를 다시 빌드한 뒤 데모 스캔으로 확인합니다.

Trivy 취약점 DB, Semgrep 규칙(`p/java`), endoflife.date 정보는 최신 데이터를 반영해야 하므로 고정하지 않고 실행할 때마다 가져옵니다. 스캔에 사용한 도구 버전은 `manifest.json`에 기록됩니다.

## 종료와 초기화

```bash
podman compose -f compose.yaml -f compose.podman.yaml down
```

Jenkins 설정, 빌드 기록, 의존성 캐시까지 지우려면 `down -v`로 볼륨도 삭제합니다. `reports/`의 결과 파일은 삭제되지 않습니다.
