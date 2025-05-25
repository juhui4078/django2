
import uuid
from typing import Optional # 과제

from ninja import NinjaAPI, Schema
from typing import List # 리스트 타입을 명시하기 위해 임포트
from .models import Todo # 우리의 Todo 모델 임포트
from django.shortcuts import get_object_or_404 # 특정 객체 가져올 때 유용
from ninja.security import APIKeyHeader # APIKeyHeader 임포트
from .models import Todo, ApiKey # ApiKey 모델 임포트
from django.contrib.auth import authenticate # Django의 기본 인증 함수 임포트
from django.contrib.auth.models import User # User 모델 임포트

# NinjaAPI 인스턴스 생성
api = NinjaAPI()

# 첫 번째 API 엔드포인트 (GET /hello)
@api.get("/hello")
def hello(request):
    return {"message": "Hello, Ninja!"}

# --- Custom API Key Authentication Class ---
# APIKeyHeader 클래스를 상속받아 Authorization 헤더에서 'Api-Key' 값을 읽어옵니다.
class MyApiKeyAuth(APIKeyHeader):
    # 헤더 이름 설정. 클라이언트는 'Authorization: Api-Key YOUR_API_KEY' 형식으로 보내야 함
    param_name = "Api-Key"
    header = "Authorization" # 클라이언트가 사용할 헤더 이름

    # 이 authenticate 메소드에서 실제 인증 로직을 구현합니다.
    # key는 헤더에서 읽어온 'Api-Key' 뒤의 실제 키 값입니다.
    def authenticate(self, request, key):
        # 1. 받은 key 값으로 ApiKey 모델에서 해당하는 객체를 찾습니다.
        try:
            api_key = ApiKey.objects.select_related('user').get(key=key)
            # select_related('user')로 사용자 정보를 미리 가져와 성능을 좋게 함

            # 2. 찾았으면 해당 ApiKey와 연결된 User 객체를 반환합니다.
            # 이 User 객체가 request.auth 에 담기게 됩니다.
            return api_key.user
        except ApiKey.DoesNotExist:
            # 3. 해당하는 ApiKey가 없으면 인증 실패 (None 반환)
            return None
            
api = NinjaAPI(auth=[MyApiKeyAuth()]) # MyApiKeyAuth 사용

# --- Schema 정의 ---
# API 응답/요청 데이터의 형식을 정의합니다.
class TodoSchema(Schema):
    id: int # 모델의 id 필드
    title: str # 모델의 title 필드
    completed: bool # 모델의 completed 필드

# Input Schema - 데이터 생성/수정 시 요청 본문의 형식을 정의합니다.
class TodoIn(Schema):
    title: str # 제목 (필수)
    completed: bool = False # 완료 여부

# --- Login Input Schema ---
# 로그인 요청 본문의 형식을 정의합니다.
class LoginIn(Schema):
    username: str
    password: str

# --- Login Success Output Schema ---
# 로그인 성공 시 응답 형식
class ApiKeyOut(Schema):
    api_key: uuid.UUID # uuid.UUID 타입으로 정의

# -- 과제부분 Schema ---
class UserProfileSchema(Schema):
    id: int
    username: str
    email: Optional[str]
    first_name: Optional[str]
    last_name: Optional[str]
    date_joined: str
    api_key: uuid.UUID

class UserProfileUpdateSchema(Schema):
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None   

# --- GET Endpoints ---

# 모든 할 일 목록 가져오기
@api.get("/todos", response=List[TodoSchema]) # 응답은 TodoSchema의 리스트 형태
def list_todos(request):
    todos = Todo.objects.all() # 모든 Todo 객체 가져오기
    # QuerySet은 바로 JSON이 안되므로, Schema를 통해 변환해서 넘겨줍니다.
    return todos # django-ninja가 QuerySet을 받으면 자동으로 Schema 리스트로 변환 시도

# 특정 할 일 하나 가져오기 (ID로 구분)
# URL 경로에 {todo_id: int} 로 경로 파라미터를 받습니다. int 타입으로 자동 검증
@api.get("/todos/{todo_id}", response=TodoSchema) # 응답은 TodoSchema 하나
def get_todo(request, todo_id: int):
    # todo_id를 사용하여 특정 Todo 객체 찾기
    # 없으면 404 Not Found 에러를 자동으로 발생시킵니다.
    todo = get_object_or_404(Todo, id=todo_id)
    return todo # django-ninja가 모델 객체를 받으면 자동으로 Schema로 변환 시도

# --- POST Endpoint (할 일 생성) ---
# 요청 본문은 TodoIn 스키마 형태로 받을 것을 명시
@api.post("/todos", response=TodoSchema) # 응답은 생성된 Todo 객체의 Schema 형태
def create_todo(request, todo_in: TodoIn):
    # todo_in 객체에는 요청 본문에서 파싱된 데이터가 들어있습니다.
    # todo_in.dict() 로 딕셔너리 형태로 만들어서 모델 생성에 사용
    todo = Todo.objects.create(**todo_in.dict())
    return todo # 생성된 객체를 반환하면 django-ninja가 TodoSchema로 변환

# --- PUT/PATCH Endpoint (할 일 수정) ---
# {todo_id: int} 로 수정할 할 일 지정, todo_in: TodoIn 으로 수정할 내용 받기
@api.put("/todos/{todo_id}", response=TodoSchema)
def update_todo(request, todo_id: int, todo_in: TodoIn):
    todo = get_object_or_404(Todo, id=todo_id) # 수정할 객체 찾기
    # todo_in.dict() 의 내용을 todo 객체에 업데이트
    for key, value in todo_in.dict().items():
        setattr(todo, key, value) # 객체의 속성(key)에 값(value) 설정
    todo.save() # 데이터베이스에 저장
    return todo # 수정된 객체를 반환

# --- DELETE Endpoint (할 일 삭제) ---
# 삭제 성공 시 204 No Content 상태 코드를 반환합니다.
@api.delete("/todos/{todo_id}")
def delete_todo(request, todo_id: int):
    todo = get_object_or_404(Todo, id=todo_id) # 삭제할 객체 찾기
    todo.delete() # 삭제!

# --- API Key 발급 EndPoint (로그인) ---
@api.post("/token", response=ApiKeyOut, auth=None) # POST 요청, 성공 시 ApiKeyOut 형식 응답
def generate_token(request, user_login: LoginIn):
    # Django의 authenticate 함수를 사용하여 사용자 이름/비밀번호 검증
    user = authenticate(
        request,
        username=user_login.username,
        password=user_login.password
    )

    # 인증 성공 시
    if user:
        # 해당 사용자의 ApiKey를 찾거나, 없으면 새로 생성합니다.
        # get_or_create: 객체가 있으면 가져오고, 없으면 생성합니다.
        api_key, created = ApiKey.objects.get_or_create(user=user)
        # 생성되었든 가져왔든 api_key 객체에는 해당 사용자의 Key가 들어있습니다.

        # 발급받거나 가져온 Key 값을 응답으로 반환합니다.
        return ApiKeyOut(api_key=api_key.key)
    else:
        # 인증 실패 시 401 Unauthorized 에러를 발생시킵니다.
        from ninja.errors import HttpError
        raise HttpError(status_code=401, message="Invalid username or password")    
    
# --- GET Endpoints (인증 및 권한 적용) ---

# 모든 할 일 목록 가져오기
@api.get("/todos", response=List[TodoSchema])
def list_todos(request):
    # 인증 성공 시 request.auth 에 User 객체가 담깁니다.
    # 이제 현재 로그인한 사용자의 할 일만 필터링해서 반환합니다.
    todos = Todo.objects.filter(owner=request.auth).all()
    return todos # django-ninja가 QuerySet을 받으면 자동으로 Schema 리스트로 변환 시도

# 특정 할 일 하나 가져오기 (인증 및 권한 적용)
# {todo_id: int} 로 경로 파라미터 받기
@api.get("/todos/{todo_id}", response=TodoSchema)
def get_todo(request, todo_id: int):
    # todo_id와 현재 로그인한 사용자를 기준으로 특정 Todo 객체 찾기
    # 해당 사용자의 할 일이 아니거나 없으면 404 Not Found 에러 발생
    todo = get_object_or_404(Todo, id=todo_id, owner=request.auth)
    return todo # django-ninja가 모델 객체를 받으면 자동으로 Schema로 변환 시도

# --- POST Endpoint (할 일 생성 - 인증 적용) ---
# 새로운 할 일 생성
@api.post("/todos", response=TodoSchema)
def create_todo(request, todo_in: TodoIn):
    # todo_in.dict() 와 함께 owner=request.auth 를 추가하여 현재 사용자로 설정
    todo = Todo.objects.create(**todo_in.dict(), owner=request.auth)
    return todo # 생성된 객체를 반환하면 django-ninja가 TodoSchema로 변환

# --- PUT/PATCH Endpoint (할 일 수정 - 인증 및 권한 적용) ---
# 할 일 수정 (인증된 사용자의 할 일 중 해당 ID의 할 일만 수정)
@api.put("/todos/{todo_id}", response=TodoSchema)
def update_todo(request, todo_id: int, todo_in: TodoIn):
    # todo_id와 현재 사용자를 기준으로 수정할 할 일 찾기
    todo = get_object_or_404(Todo, id=todo_id, owner=request.auth)
    # todo_in.dict() 의 내용을 todo 객체에 업데이트
    for key, value in todo_in.dict().items():
        setattr(todo, key, value) # 객체의 속성(key)에 값(value) 설정
    todo.save() # 데이터베이스에 저장
    return todo # 수정된 객체를 반환

# --- DELETE Endpoint (할 일 삭제 - 인증 및 권한 적용) ---
# 할 일 삭제 (인증된 사용자의 할 일 중 해당 ID의 할 일만 삭제)
@api.delete("/todos/{todo_id}")
def delete_todo(request, todo_id: int):
    # todo_id와 현재 사용자를 기준으로 삭제할 할 일 찾기
    todo = get_object_or_404(Todo, id=todo_id, owner=request.auth)
    todo.delete() # 삭제    

# 과제 : 현재 사용자 정보 조회
@api.get("/me", response=UserProfileSchema)
def get_my_profile(request):
    user = request.auth
    api_key = get_object_or_404(ApiKey, user=user)
    return UserProfileSchema(
        id=user.id,
        username=user.username,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        date_joined=user.date_joined.isoformat(),
        api_key=api_key.key
    )

# 과제 : 현재 사용자 정보 수정
@api.put("/me", response=UserProfileSchema)
def update_my_profile(request, data: UserProfileUpdateSchema):
    user = request.auth
    for field in ['email', 'first_name', 'last_name']:
        value = getattr(data, field)
        if value is not None:
            setattr(user, field, value)
    user.save()
    api_key = get_object_or_404(ApiKey, user=user)
    return UserProfileSchema(
        id=user.id,
        username=user.username,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        date_joined=user.date_joined.isoformat(),
        api_key=api_key.key
    )

# 과제 : API Key 재발급
@api.post("/me/regenerate-key", response=ApiKeyOut)
def regenerate_api_key(request):
    user = request.auth
    api_key = get_object_or_404(ApiKey, user=user)
    api_key.key = uuid.uuid4()
    api_key.save()
    return ApiKeyOut(api_key=api_key.key)    