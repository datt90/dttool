import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, status
from fastapi import Body
from fastapi.security import OAuth2PasswordBearer
from fastapi.security.http import HTTPBasic, HTTPBasicCredentials

from hgf.constants import Config
from hgf.rpc.api_server.deps import get_config

from hgf.rpc.api_server.api_schemas import AccessAndRefreshToken, AccessToken, SignupRequest
from hgf.rpc.api_server.deps import get_api_config

logger = logging.getLogger(__name__)

ALGORITHM = "HS256"

router_auth = APIRouter()

def verify_auth(api_config, username: str, password: str):
    """Verify username/password"""
    return secrets.compare_digest(username, api_config.get("username")) and secrets.compare_digest(
        password, api_config.get("password")
    )

httpbasic = HTTPBasic(auto_error=False)
security = HTTPBasic()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

def get_user_from_token(token, secret_key: str, token_type: str = "access") -> str:  
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM])
        username: str = payload.get("identity", {}).get("u")
        if username is None:
            raise credentials_exception
        if payload.get("type") != token_type:
            raise credentials_exception

    except jwt.PyJWTError:
        raise credentials_exception
    return username

def create_token(data: dict, secret_key: str, token_type: str = "access") -> str:  
    to_encode = data.copy()
    if token_type == "access":  
        expire = datetime.now(UTC) + timedelta(minutes=15)
    elif token_type == "refresh": 
        expire = datetime.now(UTC) + timedelta(days=30)
    else:
        raise ValueError()
    to_encode.update(
        {
            "exp": expire,
            "iat": datetime.now(UTC),
            "type": token_type,
        }
    )
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=ALGORITHM)
    return encoded_jwt

def http_basic_or_jwt_token(
    form_data: HTTPBasicCredentials = Depends(httpbasic),
    token: str = Depends(oauth2_scheme),
    api_config=Depends(get_api_config),
):
    if token:
        return get_user_from_token(token, api_config.get("jwt_secret_key", "super-secret"))
    elif form_data and verify_auth(api_config, form_data.username, form_data.password):
        return form_data.username

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized",
    )

# Define the /token/login endpoint.
# Example usage with curl:
# curl --location --request POST 'http://localhost:4096/api/v1/token/login' \
#   --header 'Content-Type: application/json' \
#   --header 'Authorization: Basic aGdxMjg3QGdtYWlsLmNvbTpAMTIzIQ==' \
#   --data ''
@router_auth.post("/token/login", response_model=AccessAndRefreshToken)
def token_login(
    form_data: HTTPBasicCredentials = Depends(security), api_config=Depends(get_api_config)
):
    if verify_auth(api_config, form_data.username, form_data.password):
        token_data = {"identity": {"u": form_data.username}}
        access_token = create_token(
            token_data,
            api_config.get("jwt_secret_key", "super-secret"),
            token_type="access",  
        )
        refresh_token = create_token(
            token_data,
            api_config.get("jwt_secret_key", "super-secret"),
            token_type="refresh",  
        )
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    

# Define the /token/refresh endpoint.
# Example usage with curl:
# curl --location --request POST 'http://localhost:4096/api/v1/token/refresh' \
# --header 'Content-Type: application/json' \
# --header 'Authorization: Bearer <refresh_token>' \   
@router_auth.post("/token/refresh", response_model=AccessToken)
def token_refresh(token: str = Depends(oauth2_scheme), api_config=Depends(get_api_config)):
    # Refresh token
    u = get_user_from_token(token, api_config.get("jwt_secret_key", "super-secret"), "refresh")
    token_data = {"identity": {"u": u}}
    access_token = create_token(
        token_data,
        api_config.get("jwt_secret_key", "super-secret"),
        token_type="access",  
    )
    return {"access_token": access_token}

# Define the /token/signup endpoint.
# Example usage with curl:
# curl --location --request POST 'http://localhost:4096/api/v1/token/signup' \
# --header 'Content-Type: application/json' \
# --data-raw '{
#   "username": "test@localhost.com",
#   "password": "test123!"
#}'
@router_auth.post("/token/signup", response_model=AccessAndRefreshToken)
def token_signup(
    signup: SignupRequest = Body(...),
    api_config=Depends(get_api_config)
):
    # Update the in-memory api_config with new credentials
    api_config["username"] = signup.username
    api_config["password"] = signup.password
    token_data = {"identity": {"u": signup.username}}
    access_token = create_token(
        token_data,
        api_config.get("jwt_secret_key", "super-secret"),
        token_type="access",
    )
    refresh_token = create_token(
        token_data,
        api_config.get("jwt_secret_key", "super-secret"),
        token_type="refresh",
    )
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
    }