# 기술 스택 및 제거 대상 조사

## 1. 심층 인터뷰 요약

사용자 응답을 기다리지 않고 진행해야 했기 때문에, 현재 PRD를 인터뷰 답변으로 간주했다. 핵심 가정은 다음과 같다.

- macOS 네이티브 통합이 가장 중요하다.
- 의존성은 최소화하고, 설치/배포가 단순해야 한다.
- 제거 도구 특성상 안전한 기본값, JSON 로그, 재부팅/권한 안내가 필수다.
- 장기적으로는 시그니처 DB를 업데이트 가능하게 유지해야 한다.

## 2. 기술 스택 결정

### 최종 선택

- 언어: `Swift 6`
- 빌드/패키지 관리: `Swift Package Manager`
- CLI 프레임워크: `Swift ArgumentParser`
- 테스트: `Swift Testing`
- 로그: `OSLog` + JSONL 파일
- macOS 연동: `Foundation` 중심, 필요 시 `Process`로 `launchctl`, `pkgutil`, `systemextensionsctl`, `codesign` 호출

### 선택 이유

`Swift`가 이 프로젝트에 가장 적합하다. 이유는 Apple 프레임워크 접근성이 가장 좋고, macOS 배포 시 런타임 추가 설치 부담이 적으며, 장기적으로 로그인 항목, launchd, plist, 권한 상승 주변 로직을 다루기 쉽기 때문이다. `Go`는 배포는 편하지만 Apple 플랫폼 통합이 약하고, `Rust`는 안정성은 좋지만 초기 구현 속도와 유지보수 비용이 더 높다.

`ArgumentParser`는 서브커맨드와 플래그 기반 CLI 구조에 맞고, `Swift Testing`은 파라미터화 테스트와 SPM 통합이 좋아 시그니처 기반 스캔 로직 검증에 적합하다.

## 3. 제거 대상 조사 결과

### A. 1차 확정 대상

아래 항목은 공식 벤더 페이지 또는 공공기관 설치 페이지 기준으로 macOS 후보로 볼 근거가 있다.

| 제품군 | 벤더 | 상태 | 메모 |
|---|---|---|---|
| `TouchEn nxKey` | RaonSecure | 확정 | 공식 페이지에서 Windows/Mac 지원을 명시. 공공기관 설치 페이지와 벤더 지원 페이지도 존재. |
| `WizIN-VeraPort` | WIZVERA | 확정에 준함 | 공식 사이트 검색 스니펫에서 전 OS 지원과 금융/공공 레퍼런스를 확인. 상세 페이지는 현재 환경에서 열리지 않아 구현 전 재검증 필요. |
| `INISAFE CrossWeb EX` | INITECH | 확정 | 공식 페이지에서 멀티 브라우저/멀티 OS 및 daemon 기반 구조를 확인. |

### B. 2차 유력 대상

| 제품군 | 벤더 | 상태 | 메모 |
|---|---|---|---|
| `TouchEn Transkey` | RaonSecure | 유력 | 같은 벤더군이며 공공/금융 배포 가능성이 높지만, 이 문서 작성 시점에는 macOS 개별 설치 흔적을 확인하지 못했다. |
| `TouchEn nxFirewall` | RaonSecure | 유력 | 제품군 단위로는 확인되지만, Mac 전용 제거 시그니처는 추가 수집 필요. |
| `TouchEn nxWeb` | RaonSecure | 유력 | 브라우저 보안/실행 계열 후보. 구체 아티팩트는 미확정. |
| `Key# Biz` | RaonSecure | 유력 | 인증/전자서명 계열 후보. 설치 흔적 보강 필요. |

### C. 3차 검증 필요 대상

| 제품군 | 상태 | 메모 |
|---|---|---|
| `AnySign/AnySign4PC` | 검증 필요 | 퍼플렉시티 조사에서 macOS 공식 근거를 충분히 확보하지 못했다. |
| `CrossCert/CrossEX` | 검증 필요 | historical 후보로는 타당하지만, 현재 macOS 지원 근거가 부족하다. |

## 4. 제거 시 반드시 점검할 흔적

초기 스캐너는 제품명보다 흔적 분류를 먼저 지원해야 한다.

- 앱 번들: `/Applications`, `~/Applications`
- LaunchAgents/LaunchDaemons: `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons`
- pkg receipts: `pkgutil --pkgs`, `/var/db/receipts`
- 로그인 항목/백그라운드 태스크: `sfltool dumpbtm`, 관련 설정 파일
- 브라우저 확장: Safari/Chrome 사용자 프로필
- 캐시/환경설정: `~/Library/Caches`, `~/Library/Preferences`
- privileged helper tools: `/Library/PrivilegedHelperTools`
- system extensions: `systemextensionsctl list`
- 구형 잔재: `/Library/Extensions`의 kext, launchd label, vendor 문자열 기반 plist

핵심 원칙은 "제품별 확정 시그니처 + 범용 흔적 스캔"의 병행이다. 근거가 약한 제품군은 즉시 삭제 후보로 넣지 말고 `confidence: low`로 분리해야 한다.

## 5. 초안 시그니처 스키마

```json
{
  "id": "raon.touchennxkey",
  "vendor": "RaonSecure",
  "product": "TouchEn nxKey",
  "bundleIds": [],
  "paths": [],
  "launchdLabels": [],
  "pkgReceipts": [],
  "browserExtensions": [],
  "risk": "medium",
  "confidence": "high"
}
```

## 6. 참고 자료

- RaonSecure nxKey: https://www.raonsecure.com/ko/solution/nxkey
- RaonSecure TouchEn 지원: https://www.raonsecure.com/ko/support/inquiry/touchennxkey
- 문화체육관광부 TouchEn 설치 페이지: https://www.mcst.go.kr/TouchEn/install/install.html
- WIZVERA 공식 사이트: https://www.wizvera.com/
- INISAFE CrossWeb EX: https://www.initech.com/business/finance
- Apple 배포 문서, 로그인 항목/백그라운드 태스크: https://support.apple.com/guide/deployment/manage-login-items-background-tasks-mac-depdca572563/web
- Apple 배포 문서, 시스템 확장: https://support.apple.com/guide/deployment/system-extensions-in-macos-depa5fb8376f/web
- Swift ArgumentParser: https://github.com/apple/swift-argument-parser
- Swift Testing: https://developer.apple.com/documentation/testing

## 7. 다음 단계

- `TouchEn nxKey`, `WizIN-VeraPort`, `INISAFE CrossWeb EX`부터 샘플 시그니처를 만든다.
- 실기기 또는 VM에서 설치 후 `paths`, `launchdLabels`, `pkgReceipts`를 채운다.
- `doctor` 커맨드로 권한/재부팅/잔여 흔적 점검을 먼저 구현한다.
