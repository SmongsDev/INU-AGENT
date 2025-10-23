import logging
import sys
from logging.handlers import RotatingFileHandler

# httpx 및 기타 외부 라이브러리의 INFO 로그 끄기
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("openai").setLevel(logging.WARNING)

def get_logger(name: str) -> logging.Logger:
    """
    로거 인스턴스를 생성하고 반환합니다.
    
    Args:
        name (str): 로거 이름
        
    Returns:
        logging.Logger: 설정된 로거 인스턴스
    """
    # 로거 생성
    logger = logging.getLogger(name)
    
    # 로그 레벨 설정
    logger.setLevel(logging.INFO)
    
    # 이미 핸들러가 설정되어 있다면 추가 설정하지 않음
    if logger.handlers:
        return logger
        
    # 포맷터 설정
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # 콘솔 핸들러 설정
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # 파일 핸들러 설정 (로그 파일은 최대 10MB, 최대 5개 파일 유지)
    file_handler = RotatingFileHandler(
        'app.log',
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger
