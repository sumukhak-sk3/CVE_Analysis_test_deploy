#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _trim(value: Optional[str]) -> str:
    return (value or "").strip()


def _sanitize_param(value: Optional[str]) -> str:
    s = _trim(value)
    if len(s) >= 2 and ((s[0] == '"' and s[-1] == '"') or (s[0] == "'" and s[-1] == "'")):
        s = s[1:-1].strip()
    return s


def _jenkins_get_json(url: str, username: str, token: str, timeout: int) -> Dict[str, Any]:
    req = urllib.request.Request(url)
    auth = f"{username}:{token}".encode("utf-8")
    b64 = __import__("base64").b64encode(auth).decode("ascii")
    req.add_header("Authorization", f"Basic {b64}")
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _jenkins_get_text(url: str, username: str, token: str, timeout: int) -> str:
    req = urllib.request.Request(url)
    auth = f"{username}:{token}".encode("utf-8")
    b64 = __import__("base64").b64encode(auth).decode("ascii")
    req.add_header("Authorization", f"Basic {b64}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _extract_branch(console_text: str, regexes: List[str]) -> Optional[str]:
    def _normalize_branch(candidate: str) -> str:
        c = _trim(candidate)
        prefixes = (
            "refs/heads/",
            "remotes/origin/",
            "origin/",
        )
        for prefix in prefixes:
            if c.startswith(prefix):
                c = c[len(prefix):]
                break
        return c

    for pattern in regexes:
        try:
            matches = list(re.finditer(pattern, console_text, flags=re.IGNORECASE | re.MULTILINE))
        except re.error:
            continue
        for match in reversed(matches):
            candidate = _normalize_branch(match.group(1) if match.groups() else "")
            if candidate and re.match(r"^[A-Za-z0-9._/\-]+$", candidate):
                return candidate
    return None


def _scan_builds_for_branch(
    builds: List[Dict[str, Any]],
    regexes: List[str],
    username: str,
    token: str,
    request_timeout_seconds: int,
    source_prefix: str,
) -> Tuple[Optional[str], str]:
    for build in builds:
        build_url = _trim(build.get("url"))
        if not build_url:
            continue
        console_url = f"{build_url.rstrip('/')}/consoleText"
        try:
            text = _jenkins_get_text(console_url, username, token, request_timeout_seconds)
        except urllib.error.URLError as exc:
            return None, f"console_fetch_failed:{exc}"
        branch = _extract_branch(text, regexes)
        if branch:
            build_num = build.get("number")
            return branch, f"{source_prefix}_{build_num}"
    return None, "branch_not_found"


def _resolve_branch_from_upstream(
    upstream_cfg: Dict[str, Any],
    username: str,
    token: str,
) -> Tuple[Optional[str], str]:
    builds_api_url = _trim(upstream_cfg.get("job_builds_api_url"))
    if not builds_api_url:
        return None, "missing_builds_api_url"

    timeout_seconds = int(upstream_cfg.get("branch_poll_timeout_seconds", 600))
    interval_seconds = int(upstream_cfg.get("branch_poll_interval_seconds", 10))
    request_timeout_seconds = int(upstream_cfg.get("http_timeout_seconds", 30))
    max_builds = int(upstream_cfg.get("max_builds_to_scan", 20))
    running_build_grace_seconds = int(upstream_cfg.get("running_build_grace_seconds", 120))
    regexes = upstream_cfg.get("branch_regexes") or [
        r'"branch"\s*:\s*"([^"\\]+)"',
        r'"git_branch"\s*:\s*"([^"\\]+)"',
        r"'branch'\s*:\s*'([^'\\]+)'",
    ]

    end_time = time.time() + timeout_seconds
    running_wait_deadline = time.time() + max(running_build_grace_seconds, 0)
    latest_error = ""
    poll_count = 0

    while time.time() < end_time:
        poll_count += 1
        try:
            payload = _jenkins_get_json(builds_api_url, username, token, request_timeout_seconds)
            builds = payload.get("builds") or []
            candidates = builds[:max_builds]

            running_builds = [b for b in candidates if bool(b.get("building"))]
            if running_builds:
                elapsed = timeout_seconds - int(max(end_time - time.time(), 0))
                print(
                    f"[branch-resolver] poll={poll_count} running_builds={len(running_builds)} elapsed={elapsed}s waiting_for_branch",
                    flush=True,
                )
                branch, source = _scan_builds_for_branch(
                    running_builds,
                    regexes,
                    username,
                    token,
                    request_timeout_seconds,
                    "upstream_running_build",
                )
                if branch:
                    print(f"[branch-resolver] branch found from running build: {branch}", flush=True)
                    return branch, source
                latest_error = source
                if time.time() >= running_wait_deadline:
                    print(
                        "[branch-resolver] running build grace window elapsed; falling back to last successful build lookup",
                        flush=True,
                    )
                else:
                    time.sleep(max(interval_seconds, 1))
                    continue

            successful_builds = [b for b in candidates if (b.get("result") or "").upper() == "SUCCESS"]
            if successful_builds:
                print(
                    f"[branch-resolver] checking last successful builds count={len(successful_builds)}",
                    flush=True,
                )
                branch, source = _scan_builds_for_branch(
                    successful_builds,
                    regexes,
                    username,
                    token,
                    request_timeout_seconds,
                    "upstream_last_successful_build",
                )
                if branch:
                    print(f"[branch-resolver] branch found from successful build: {branch}", flush=True)
                    return branch, source
                return None, "last_successful_build_no_branch_found"

            return None, "no_running_or_successful_build_found"
        except Exception as exc:
            latest_error = str(exc)
            print(f"[branch-resolver] poll={poll_count} error={latest_error}", flush=True)

        time.sleep(max(interval_seconds, 1))

    return None, f"poll_timeout:{latest_error}" if latest_error else "poll_timeout"


def _resolve_delta_vuln_path(
    workspace: Path,
    run_root: Path,
    cfg: Dict[str, Any],
) -> Tuple[str, str]:
    s3_cfg = cfg.get("s3") or {}
    bucket_name = _trim(s3_cfg.get("bucket_name"))
    if not bucket_name:
        raise RuntimeError("s3.bucket_name is required in automation config")

    prefix = _trim(s3_cfg.get("prefix", ""))
    aws_region = _trim(s3_cfg.get("aws_region", "us-west-1"))
    delta_subdir = _trim(s3_cfg.get("delta_output_subdir", "s3_delta"))
    state_file_name = _trim(s3_cfg.get("state_file_name", ".last_processed_s3_file.json"))

    output_dir = (run_root / delta_subdir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    state_file = (output_dir / state_file_name).resolve()

    before_state = {}
    if state_file.exists():
        try:
            before_state = json.loads(state_file.read_text(encoding="utf-8"))
        except Exception:
            before_state = {}

    env = os.environ.copy()
    env["AWS_REGION"] = aws_region
    env["PYTHONUNBUFFERED"] = "1"

    cmd = [
        sys.executable,
        str((workspace / "please.py").resolve()),
        "--output-dir",
        str(output_dir),
        "--bucket-name",
        bucket_name,
        "--prefix",
        prefix,
        "--state-file",
        str(state_file),
        "--aws-region",
        aws_region,
    ]

    completed = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if completed.stdout:
        print(completed.stdout.rstrip())
    if completed.stderr:
        print(completed.stderr.rstrip(), file=sys.stderr)
    if completed.returncode != 0:
        raise RuntimeError(f"please.py failed with exit code {completed.returncode}")

    after_state = {}
    if state_file.exists():
        try:
            after_state = json.loads(state_file.read_text(encoding="utf-8"))
        except Exception:
            after_state = {}

    delta_file = _trim(after_state.get("delta_file")) or _trim(before_state.get("delta_file"))
    if not delta_file:
        raise RuntimeError("Unable to determine delta_file from state file")

    delta_path = Path(delta_file)
    if not delta_path.is_absolute():
        delta_path = (output_dir / delta_path).resolve()

    if not delta_path.exists():
        raise RuntimeError(f"Delta file does not exist: {delta_path}")

    return str(delta_path), "s3_delta"


def main() -> int:
    parser = argparse.ArgumentParser(description="Resolve automated Jenkins inputs for branch and vulnerabilities file")
    parser.add_argument("--config", required=True, help="Path to automation config json")
    parser.add_argument("--workspace", required=True, help="Workspace path")
    parser.add_argument("--run-root", required=True, help="Run root path")
    parser.add_argument("--output-env", required=True, help="Where to write resolved shell exports")
    parser.add_argument("--repository-override", default="", help="Explicit REPOSITORY_URL override from Jenkins parameter")
    parser.add_argument("--branch-override", default="", help="Explicit BRANCH override from Jenkins parameter")
    parser.add_argument("--vulnerabilities-path-override", default="", help="Explicit VULNERABILITIES_FILE_PATH override")
    args = parser.parse_args()

    workspace = Path(args.workspace).resolve()
    run_root = Path(args.run_root).resolve()
    run_root.mkdir(parents=True, exist_ok=True)

    cfg = _read_json(Path(args.config).resolve())

    repo_default = _trim(cfg.get("repository_url_default", ""))
    branch_fallback = _trim(cfg.get("branch_fallback", "develop/9.2"))

    repo_override = _sanitize_param(args.repository_override)
    branch_override = _sanitize_param(args.branch_override)
    vuln_override = _sanitize_param(args.vulnerabilities_path_override)

    resolved_repo = repo_override or repo_default
    repo_source = "manual" if repo_override else "config_default"
    if not resolved_repo:
        raise RuntimeError("No repository URL resolved. Set REPOSITORY_URL or repository_url_default in config.")

    jenkins_user = _trim(os.getenv("JENKINS_API_USER"))
    jenkins_token = _trim(os.getenv("JENKINS_API_TOKEN"))

    resolved_branch = ""
    branch_source = ""

    if branch_override:
        resolved_branch = branch_override
        branch_source = "manual"
    elif jenkins_user and jenkins_token:
        branch, source = _resolve_branch_from_upstream(cfg.get("upstream") or {}, jenkins_user, jenkins_token)
        if branch:
            resolved_branch = branch
            branch_source = source
        else:
            resolved_branch = branch_fallback
            branch_source = f"fallback:{source}"
    else:
        resolved_branch = branch_fallback
        branch_source = "fallback:missing_jenkins_credentials"

    if not resolved_branch:
        resolved_branch = branch_fallback
        branch_source = "fallback:empty_branch"

    if vuln_override:
        resolved_vuln_path = vuln_override
        vuln_source = "manual"
    else:
        resolved_vuln_path, vuln_source = _resolve_delta_vuln_path(workspace, run_root, cfg)

    output_env = Path(args.output_env).resolve()
    output_env.write_text(
        "\n".join(
            [
                f'export AUTO_REPOSITORY_URL="{resolved_repo}"',
                f'export AUTO_REPOSITORY_URL_SOURCE="{repo_source}"',
                f'export AUTO_BRANCH="{resolved_branch}"',
                f'export AUTO_BRANCH_SOURCE="{branch_source}"',
                f'export AUTO_VULNERABILITIES_FILE_PATH="{resolved_vuln_path}"',
                f'export AUTO_VULNERABILITIES_FILE_PATH_SOURCE="{vuln_source}"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"Resolved repository URL ({repo_source}): {resolved_repo}")
    print(f"Resolved branch ({branch_source}): {resolved_branch}")
    print(f"Resolved vulnerabilities file ({vuln_source}): {resolved_vuln_path}")
    print(f"Wrote automation exports: {output_env}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Automation input resolution failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
