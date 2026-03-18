# gura-remover-mac

macOS에서 국내 금융/공공 사이트 이용 과정에서 설치된 보안 모듈, 런처, 보조 프로그램 흔적을 탐지하고 정리하기 위한 CLI 도구입니다.

## ⚠️ 이 프로젝트는 현재 개발 중인 알파 버전입니다

> 🚨 탐지 시그니처와 제거 로직이 계속 바뀌고 있으며, 오탐 또는 과삭제 가능성이 아직 있습니다.  
> 🧪 실제 삭제 작업 전에는 반드시 `--dry-run`으로 먼저 확인하고, 백업 세션이 생성되는지 검토한 뒤 진행하세요.

## 배경

이 프로젝트는 Windows용 **구라제거기/구라탐지기**에서 영감을 받아 시작했습니다. 다만 목표는 단순 포팅이 아니라, macOS 환경에 맞는 탐지·백업·복구 흐름을 갖춘 CLI 운영 도구를 만드는 것입니다.

## 현재 제공 기능

- `scan`, `list`: 현재 시스템에서 탐지된 항목 조회
- `doctor`: 권한, 백업, 시그니처, 시스템 명령 상태 점검
- `remove`, `remove-safe`: 선택 항목 또는 안전한 항목 제거
- `restore`: 백업 세션 복구
- `history`: 삭제/복구 이력 조회
- `signatures update`: 원격 시그니처 번들 업데이트

## 현재 프로젝트 상태

- SwiftPM 기반 macOS CLI 알파 버전입니다.
- `Wizvera`, `AhnLab ASTx`, `nProtect Online Security V1`, `CrossCert` 계열 흔적을 우선 탐지합니다.
- `remove`는 파일 삭제뿐 아니라 관련 프로세스 종료, `launchd` 등록 해제, `pkg receipt` 정리, 시스템 확장 제거 시도까지 수행합니다.
- 실제 운영 중 확인된 범위에서 `Wizvera`, `AhnLab`, `nProtect` 제거 흐름을 점검했습니다.
- 아직 시그니처 정밀도, 시스템 확장 처리, 벤더별 특수 제거 경로는 계속 보강 중입니다.

## 빠른 시작

```bash
make build
make scan ARGS='--json'
make doctor ARGS='--json'
make remove ARGS='--id wizvera.delfino --yes --dry-run'
```

고위험 항목은 `--force-high-risk`가 필요하고, 시스템 범위 삭제는 보통 `sudo`가 필요합니다.

예시:

```bash
sudo make remove ARGS='--id ahnlab.astx --yes --force-high-risk'
sudo make remove ARGS='--id inca.nprotectonlinesecurity --yes --force-high-risk'
```

## 발견된 모든 항목 제거

한 번에 스캔부터 전체 제거까지 진행하려면 아래 명령을 사용할 수 있습니다.

먼저 계획 확인:

```bash
sudo make remove-all-dry-run
```

실제 실행:

```bash
sudo make remove-all
```

내부적으로는 안전한 항목과 고위험 항목을 나눠 처리합니다. 현재 기준으로 `AhnLab ASTx`, `nProtect Online Security V1`은 `high risk`라서 `remove-all`이 별도 단계로 함께 처리합니다.

수동으로 나눠 실행하려면 아래 순서를 사용할 수 있습니다.

먼저 계획 확인:

```bash
sudo make remove-safe ARGS='--yes --dry-run'
sudo make remove ARGS='--id ahnlab.astx --yes --force-high-risk --dry-run'
sudo make remove ARGS='--id inca.nprotectonlinesecurity --yes --force-high-risk --dry-run'
```

실제 실행:

```bash
sudo make remove-safe ARGS='--yes'
sudo make remove ARGS='--id ahnlab.astx --yes --force-high-risk'
sudo make remove ARGS='--id inca.nprotectonlinesecurity --yes --force-high-risk'
```

중요:

- `remove-safe`는 기본적으로 `high risk` 항목을 포함하지 않습니다.
- 현재 `AhnLab ASTx`, `nProtect Online Security V1`은 `high risk`라 별도 명령이 필요합니다.
- 현재 `remove`는 파일 경로 삭제뿐 아니라 관련 프로세스 종료, `launchd` 등록 해제, `pkg receipt` 정리, `nProtect` 시스템 확장 제거 시도까지 함께 수행합니다.
- `systemextensionsctl uninstall`은 macOS 상태에 따라 사용자 승인 또는 재부팅이 추가로 필요할 수 있습니다.
- `sudo make ...`로 실행해도 빌드는 원래 사용자 권한으로 수행되도록 조정되어 있습니다.

## nProtect 잔여 시스템 확장 정리

실제 운영 중 `nProtect`는 CLI 제거 후에도 `com.nprotect.nosfw` 시스템 확장이 남을 수 있었습니다. 이 경우 아래 경로에서 수동 정리가 가능했습니다.

1. `시스템 설정 > 일반 > 로그인 항목 및 확장 프로그램`
2. 아래쪽 `Extensions` 영역에서 `i` 버튼 또는 세부 보기 진입
3. `Network Extensions` 항목 확인
4. `nosfw` 또는 `nProtect` 관련 토글/항목이 있으면 끄고 제거

이 방법으로 현재 환경에서는 잔여 `nProtect` 시스템 확장을 정리할 수 있었습니다.

## 앞으로 진행할 일

- `doctor`와 `scan`에서 고아 시스템 확장과 사용자 개입 필요 상태를 더 명확히 표시
- 벤더별 특수 제거 경로를 시그니처와 제거 로직에 단계적으로 반영
- `nProtect`처럼 UI 확인이 필요한 항목에 대해 후속 안내 메시지 강화
- README와 운영 문서를 실제 제거 사례 중심으로 계속 업데이트

## 참고

- `make help`로 전체 운영 명령을 볼 수 있습니다.
- 기획/조사 문서는 [docs/PRD.md](./docs/PRD.md), [docs/stack-and-target-research.md](./docs/stack-and-target-research.md)에 있습니다.
