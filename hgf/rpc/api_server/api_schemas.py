from pydantic import AwareDatetime, BaseModel, RootModel, SerializeAsAny, model_validator

class Ping(BaseModel):
  status: str

class Version(BaseModel):
  version: str

class AccessToken(BaseModel):
    access_token: str

class AccessAndRefreshToken(AccessToken):
    refresh_token: str

class SignupRequest(BaseModel):
    username: str
    password: str