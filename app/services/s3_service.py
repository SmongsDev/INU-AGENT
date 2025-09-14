import base64
import boto3
import os
from datetime import datetime
from typing import Optional
import uuid
from botocore.exceptions import NoCredentialsError, ClientError

class S3Service:
    def __init__(self):
        self.bucket_name = os.getenv("S3_BUCKET_NAME")
        self.s3_client = boto3.client('s3')

    def upload_base64_image(self, base64_data: str, file_extension: str = "png") -> Optional[str]:
        try:
            # Base64 데이터가 data URL 형식인지 확인하고 실제 데이터만 추출
            if "," in base64_data:
                base64_data = base64_data.split(",")[1]

            # Base64 디코딩
            image_data = base64.b64decode(base64_data)

            # 파일명 생성 (UUID + 확장자)
            file_name = f"{uuid.uuid4()}.{file_extension}"

            # 현재 날짜를 이용한 경로 생성
            now = datetime.now()
            year = now.strftime("%Y")
            month = now.strftime("%m")
            day = now.strftime("%d")

            # S3 키 생성
            s3_key = f"thumbnails/{year}/{month}/{day}/{file_name}"

            # S3에 업로드
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=s3_key,
                Body=image_data,
                ContentType=f"image/{file_extension}"
            )

            return s3_key

        except (NoCredentialsError, ClientError, Exception) as e:
            print(f"S3 upload error: {e}")
            return None

    def get_file_url(self, s3_key: str) -> str:
        return f"https://{self.bucket_name}.s3.amazonaws.com/{s3_key}"