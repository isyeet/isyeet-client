#!/usr/bin/env python3
"""Exercise the real release wrapper using synthetic archives and a no-op build tool."""
import os
import plistlib
from pathlib import Path
import shutil
import subprocess
import tempfile

source = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="isyeet-release-check-") as directory:
    root = Path(directory)
    (root / "scripts").mkdir()
    (root / "Config").mkdir()
    shutil.copy(source / "scripts/testflight.sh", root / "scripts/testflight.sh")
    options = plistlib.loads((source / "Config/ExportOptions-TestFlight.plist").read_bytes())
    (root / "Config/ExportOptions-TestFlight.plist").write_bytes(plistlib.dumps(options))
    (root / "bin").mkdir()
    build_tool = root / "bin/xcodebuild"
    build_tool.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$ISYEET_TEST_ARGUMENTS"\n')
    build_tool.chmod(0o700)
    arguments = root / "arguments"
    env = {key: value for key, value in os.environ.items() if not key.startswith("ISYEET_ASC_")}
    env.update(PATH=str(root / "bin") + ":" + env.get("PATH", ""), ISYEET_TEST_ARGUMENTS=str(arguments))
    for build, origin, environment in [("9", "https://api-staging.isyeet.io", None), ("11", "https://api.isyeet.io", "production")]:
        app = root / f"build/ISYEET-{build}.xcarchive/Products/Applications/ISYEET.app"
        app.mkdir(parents=True)
        info = dict(CFBundleIdentifier="com.isyeet.app", CFBundleVersion=build, ISYEETServerURL=origin,
                    ISYEETAllowLoopbackHTTP="NO", ITSAppUsesNonExemptEncryption=False)
        if environment:
            info["ISYEETEnvironment"] = environment
        (app / "Info.plist").write_bytes(plistlib.dumps(info))

    def run(args, successful, invokes=False, extra=None):
        arguments.unlink(missing_ok=True)
        result = subprocess.run(["bash", str(root / "scripts/testflight.sh"), *args], env=env | (extra or {}),
                                capture_output=True, text=True)
        assert (result.returncode == 0) == successful, (args, result.stderr)
        assert arguments.exists() == invokes, args

    run(["export", "9", "staging"], True, True)
    run(["export", "11", "production"], True, True)
    run(["export", "11", "staging"], False)
    run(["export", "9", "production"], False)
    run(["export", "11"], False)
    run(["export", "11", "unknown"], False)
    run(["archive", "11", "production"], False)  # Never clobber an archive.
    run(["export", "11", "production"], False, extra={"ISYEET_ASC_KEY_ID": "SYNTHETIC1"})
    options["testFlightInternalTestingOnly"] = False
    (root / "Config/ExportOptions-TestFlight.plist").write_bytes(plistlib.dumps(options))
    run(["export", "11", "production"], False)
print("PASS explicit origins, legacy staging, internal-only scope, credential completeness, and no archive overwrite")
