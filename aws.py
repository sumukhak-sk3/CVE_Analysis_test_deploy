import boto3
import os
from botocore.exceptions import ClientError

AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")
AWS_REGION = os.getenv("AWS_REGION", "us-west-1")  # change if needed
BUCKET_NAME = "nios-dtrack-vuln-reports"
PREFIX = ""  # optional: e.g. "folder/subfolder/"

def list_s3_files(bucket_name, prefix=""):
    kwargs = {"region_name": AWS_REGION}
    if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY:
        kwargs["aws_access_key_id"] = AWS_ACCESS_KEY_ID
        kwargs["aws_secret_access_key"] = AWS_SECRET_ACCESS_KEY
    s3 = boto3.client("s3", **kwargs)

    try:
        paginator = s3.get_paginator("list_objects_v2")
        pages = paginator.paginate(Bucket=bucket_name, Prefix=prefix)

        found = False
        for page in pages:
            for obj in page.get("Contents", []):
                print(obj["Key"])
                found = True

        if not found:
            print("No files found.")

    except ClientError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    list_s3_files(BUCKET_NAME, PREFIX)