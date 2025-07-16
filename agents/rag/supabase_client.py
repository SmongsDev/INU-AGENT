import os
import dotenv
from supabase.client import Client, create_client

dotenv.load_dotenv()
'''
get_supabase_client는 Supabase 클라이언트를 반환합니다.

Args:
    None

Returns:    
    Client: Supabase 클라이언트 인스턴스
'''
def get_supabase_client() -> Client:
    supabase_url = os.environ.get("SUPABASE_URL")
    supabase_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
    if not supabase_url or not supabase_key:
        raise ValueError("Supabase 환경변수가 설정되지 않았습니다.")
        
    return create_client(supabase_url, supabase_key)



