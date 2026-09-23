#!/usr/bin/env bash
# Uses the existing Xcode Apple account or an explicitly configured ASC team key.
# Usage: bash scripts/testflight.sh archive|export|upload BUILD_NUMBER staging|production
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
isyeet_mode=${1:-}
isyeet_build=${2:-}
isyeet_environment=${3:-}
if [[ $# != 3 || ! $isyeet_build =~ ^[1-9][0-9]*$ || ( $isyeet_environment != staging && $isyeet_environment != production ) ]]; then
  echo 'Usage: bash scripts/testflight.sh archive|export|upload BUILD_NUMBER staging|production' >&2
  exit 2
fi
case "$isyeet_environment" in
  staging) isyeet_configuration=Release ;;
  production) isyeet_configuration=Production ;;
esac
isyeet_auth_args=(-allowProvisioningUpdates)
isyeet_key_path=${ISYEET_ASC_KEY_PATH:-}
isyeet_key_id=${ISYEET_ASC_KEY_ID:-}
isyeet_issuer_id=${ISYEET_ASC_ISSUER_ID:-}
if [[ -n $isyeet_key_path || -n $isyeet_key_id || -n $isyeet_issuer_id ]]; then
  if [[ -z $isyeet_key_path || -z $isyeet_key_id || -z $isyeet_issuer_id ]]; then
    echo 'Set ISYEET_ASC_KEY_PATH, ISYEET_ASC_KEY_ID and ISYEET_ASC_ISSUER_ID together, or leave all three unset.' >&2
    exit 2
  fi
  if [[ ! -f $isyeet_key_path || ! -r $isyeet_key_path ]]; then
    echo 'ISYEET_ASC_KEY_PATH must name a readable regular file.' >&2
    exit 2
  fi
  if [[ ! $isyeet_key_id =~ ^[A-Z0-9]{10}$ ]]; then
    echo 'ISYEET_ASC_KEY_ID must be a 10-character uppercase letter/digit key identifier.' >&2
    exit 2
  fi
  if [[ ! $isyeet_issuer_id =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]]; then
    echo 'ISYEET_ASC_ISSUER_ID must use the UUID format shown in App Store Connect.' >&2
    exit 2
  fi
  # Keep paths and identifiers as separate arguments; never read or print the key.
  isyeet_auth_args+=(-authenticationKeyPath "$isyeet_key_path"
                     -authenticationKeyID "$isyeet_key_id"
                     -authenticationKeyIssuerID "$isyeet_issuer_id")
fi
isyeet_archive="build/ISYEET-$isyeet_build.xcarchive"
isyeet_export="build/testflight-$isyeet_build"
validate_archive() {
    python3 - "$isyeet_archive" "$isyeet_build" "$isyeet_environment" <<'PY'
import plistlib, sys
from pathlib import Path
archive, build, environment = sys.argv[1:]
info = plistlib.loads((Path(archive) / 'Products/Applications/ISYEET.app/Info.plist').read_bytes())
assert info['CFBundleIdentifier'] == 'com.isyeet.app', 'Unexpected app identity'
assert info['CFBundleVersion'] == build, 'Unexpected build number'
expected_origin = {'staging': 'https://api-staging.isyeet.io', 'production': 'https://api.isyeet.io'}[environment]
assert info['ISYEETServerURL'] == expected_origin, 'Archive relay does not match requested environment'
assert info.get('ISYEETEnvironment', 'staging') == environment, 'Archive environment mismatch'
assert info['ISYEETAllowLoopbackHTTP'] == 'NO', 'Release must not enable loopback auth'
assert info['ITSAppUsesNonExemptEncryption'] is False, 'Use the approved internal-test encryption declaration'
options = plistlib.loads(Path('Config/ExportOptions-TestFlight.plist').read_bytes())
assert options['testFlightInternalTestingOnly'] is True, 'This declaration is scoped to private internal testing'
assert options['method'] == 'app-store-connect' and options['teamID'] == 'KBRQXAWK93', 'Unexpected distribution scope'
assert options['destination'] == 'export' and options['manageAppVersionAndBuildNumber'] is False, 'Unexpected export behavior'
assert 'NSAppTransportSecurity' not in info, 'Release must not allow insecure transport'
print('Verified ISYEET ' + environment + ' archive metadata; private internal testing only.')
PY
}
case "$isyeet_mode" in
  archive)
    if [[ -e "$isyeet_archive" ]]; then
      echo 'Archive already exists. Choose a new build number; existing archives are never overwritten.' >&2
      exit 2
    fi
    xcodebuild -project ISYEET.xcodeproj -scheme ISYEET -configuration "$isyeet_configuration" \
      -destination 'generic/platform=iOS' -archivePath "$isyeet_archive" \
      -derivedDataPath ".build/testflight-$isyeet_environment" "${isyeet_auth_args[@]}" \
      DEVELOPMENT_TEAM=KBRQXAWK93 CURRENT_PROJECT_VERSION="$isyeet_build" archive
    validate_archive
    ;;
  export|upload)
    validate_archive
    isyeet_options=Config/ExportOptions-TestFlight.plist
    if [[ $isyeet_mode == upload ]]; then
      isyeet_options="build/UploadOptions-TestFlight-$isyeet_build.plist"
      python3 - "$isyeet_options" <<'PY'
import plistlib, sys
from pathlib import Path
options = plistlib.loads(Path('Config/ExportOptions-TestFlight.plist').read_bytes())
options['destination'] = 'upload'
Path(sys.argv[1]).write_bytes(plistlib.dumps(options))
PY
    fi
    xcodebuild -exportArchive -archivePath "$isyeet_archive" \
      -exportPath "$isyeet_export" -exportOptionsPlist "$isyeet_options" \
      "${isyeet_auth_args[@]}"
    ;;
  *) echo 'Expected archive, export, or upload.' >&2; exit 2 ;;
esac
