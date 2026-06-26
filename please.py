import argparse
import csv
import io
import json
import os
from pathlib import Path
from typing import Dict, List, Tuple

import boto3
from botocore.exceptions import ClientError

AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")
AWS_REGION = os.getenv("AWS_REGION", "us-west-1")
BUCKET_NAME = "nios-dtrack-vuln-reports"
PREFIX = ""
STATE_FILE_NAME = ".last_processed_s3_file.json"

def build_s3_client(region_name: str = AWS_REGION):
    kwargs = {"region_name": region_name}
    if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY:
        kwargs["aws_access_key_id"] = AWS_ACCESS_KEY_ID
        kwargs["aws_secret_access_key"] = AWS_SECRET_ACCESS_KEY
    return boto3.client("s3", **kwargs)

def list_csv_objects(s3, bucket_name: str, prefix: str = "") -> List[Dict]:
    paginator = s3.get_paginator("list_objects_v2")
    pages = paginator.paginate(Bucket=bucket_name, Prefix=prefix)

    objects = []
    for page in pages:
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith("/"):
                continue
            if not key.lower().endswith(".csv"):
                continue
            objects.append(
                {
                    "Key": key,
                    "LastModified": obj["LastModified"],
                    "ETag": obj.get("ETag", ""),
                    "Size": obj.get("Size", 0),
                }
            )

    objects.sort(key=lambda x: x["LastModified"])
    return objects

def read_csv_from_s3(s3, bucket_name: str, key: str) -> Tuple[List[str], List[Dict[str, str]]]:
    response = s3.get_object(Bucket=bucket_name, Key=key)
    content = response["Body"].read().decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(content))
    headers = reader.fieldnames or []
    rows = list(reader)
    return headers, rows

def read_csv_from_file(path: Path) -> Tuple[List[str], List[Dict[str, str]]]:
    content = path.read_text(encoding="utf-8-sig")
    reader = csv.DictReader(io.StringIO(content))
    headers = reader.fieldnames or []
    rows = list(reader)
    return headers, rows

def download_s3_file(s3, bucket_name: str, key: str, output_dir: Path) -> Path:
    destination = output_dir / Path(key).name
    s3.download_file(bucket_name, key, str(destination))
    return destination

def load_state(state_file: Path) -> Dict:
    if state_file.exists():
        try:
            return json.loads(state_file.read_text())
        except Exception:
            return {}
    return {}

def save_state(state_file: Path, data: Dict) -> None:
    state_file.write_text(json.dumps(data, indent=2))

def normalize_value(value):
    if value is None:
        return ""
    return str(value).strip()

def row_identity(row: Dict[str, str], headers: List[str]) -> str:
    cve_id = normalize_value(row.get("CVE_ID"))
    if cve_id:
        return cve_id
    return "||".join(normalize_value(row.get(h, "")) for h in headers)

def find_new_rows(previous_rows: List[Dict[str, str]], latest_rows: List[Dict[str, str]], headers: List[str]) -> List[Dict[str, str]]:
    previous_ids = {row_identity(row, headers) for row in previous_rows}
    seen_latest = set()
    new_rows = []

    for row in latest_rows:
        rid = row_identity(row, headers)
        if rid in seen_latest:
            continue
        seen_latest.add(rid)
        if rid not in previous_ids:
            new_rows.append(row)

    return new_rows

def write_csv(file_path: Path, headers: List[str], rows: List[Dict[str, str]]) -> None:
    with file_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

def main():
    parser = argparse.ArgumentParser(
        description="Download the latest S3 CSV and write only newly introduced CVEs compared to the previous CSV"
    )
    parser.add_argument("--output-dir", required=True, help="Local directory for downloaded latest file and delta CSV")
    parser.add_argument("--bucket-name", default=BUCKET_NAME, help="S3 bucket name")
    parser.add_argument("--prefix", default=PREFIX, help="Optional S3 prefix")
    parser.add_argument("--state-file", default=None, help="Optional state file path")
    parser.add_argument("--aws-region", default=AWS_REGION, help="AWS region for S3")
    parser.add_argument(
        "--baseline-key",
        default="",
        help="Optional fixed baseline CSV key in S3. If set, each latest upload is compared against this baseline.",
    )
    parser.add_argument(
        "--baseline-local-path",
        default="",
        help="Optional absolute local path to baseline CSV. If set, it takes precedence over --baseline-key.",
    )
    parser.add_argument(
        "--latest-key",
        default="",
        help="Optional explicit latest CSV key to process (for trigger-captured uploads).",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    state_file = Path(args.state_file) if args.state_file else output_dir / STATE_FILE_NAME
    state = load_state(state_file)

    s3 = build_s3_client(args.aws_region)

    try:
        objects = list_csv_objects(s3, args.bucket_name, args.prefix)
        if not objects:
            print("No CSV files found in S3.")
            return

        objects_by_key = {obj["Key"]: obj for obj in objects}

        latest_key_override = (args.latest_key or "").strip()
        baseline_key_override = (args.baseline_key or "").strip()
        baseline_local_path_override = (args.baseline_local_path or "").strip()

        if latest_key_override:
            latest_obj = objects_by_key.get(latest_key_override)
            if latest_obj is None:
                raise RuntimeError(
                    f"Configured latest key not found in S3 listing: {latest_key_override}"
                )
        else:
            latest_obj = objects[-1]

        previous_obj = None
        previous_rows = None
        if baseline_local_path_override:
            baseline_local_path = Path(baseline_local_path_override)
            if not baseline_local_path.is_absolute():
                raise RuntimeError(
                    f"Configured baseline local path must be absolute: {baseline_local_path_override}"
                )
            if not baseline_local_path.exists():
                raise RuntimeError(
                    f"Configured baseline local file not found: {baseline_local_path}"
                )
            _, previous_rows = read_csv_from_file(baseline_local_path)
        elif baseline_key_override:
            previous_obj = objects_by_key.get(baseline_key_override)
            if previous_obj is None:
                raise RuntimeError(
                    f"Configured baseline key not found in S3 listing: {baseline_key_override}"
                )
        elif len(objects) >= 2:
            previous_obj = objects[-2]

        latest_key = latest_obj["Key"]
        latest_etag = latest_obj["ETag"]

        if state.get("latest_key") == latest_key and state.get("latest_etag") == latest_etag:
            print(f"No new latest file. Already processed: {latest_key}")
            return

        latest_local_path = download_s3_file(s3, args.bucket_name, latest_key, output_dir)
        print(f"Downloaded latest file: {latest_key} -> {latest_local_path}")

        latest_headers, latest_rows = read_csv_from_s3(s3, args.bucket_name, latest_key)
        if not latest_headers:
            print("Latest CSV has no headers.")
            return

        if previous_rows is None and previous_obj is None:
            delta_rows = []
            print("Only one CSV exists in S3, so there is no previous file to compare against.")
        else:
            if previous_rows is None:
                previous_key = previous_obj["Key"]
                _, previous_rows = read_csv_from_s3(s3, args.bucket_name, previous_key)
            delta_rows = find_new_rows(previous_rows, latest_rows, latest_headers)
            if baseline_local_path_override:
                print(f"Compared latest file '{latest_key}' against fixed local baseline file '{baseline_local_path_override}'")
            elif baseline_key_override:
                print(f"Compared latest file '{latest_key}' against fixed baseline file '{previous_key}'")
            else:
                print(f"Compared latest file '{latest_key}' against previous file '{previous_key}'")
            print(f"New CVEs found: {len(delta_rows)}")

        delta_file = output_dir / f"new_cves_{Path(latest_key).stem}.csv"
        write_csv(delta_file, latest_headers, delta_rows)
        print(f"Delta CSV written to: {delta_file}")

        save_state(
            state_file,
            {
                "latest_key": latest_key,
                "latest_etag": latest_etag,
                "latest_local_path": str(latest_local_path),
                "delta_file": str(delta_file),
                "new_cve_count": len(delta_rows),
            },
        )
        print(f"State updated: {state_file}")

    except ClientError as e:
        print(f"AWS error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
