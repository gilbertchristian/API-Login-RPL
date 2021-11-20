import json
# import sys
from fastapi import FastAPI, HTTPException

from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "gibettsukalari"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
USER = ''

with open("user.json", "r") as read_file:
    list_of_users = json.load(read_file)

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    for user_data in db['data']:
        if user_data['username'] == username:
            return user_data
 
def authenticate_user(username: str, password: str):
    for user in list_of_users['data']:
        if user['username'] == username and verify_password(password, user['hashed_password']):
            return user
    return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(list_of_users, username=token_data.username)
    if user is None:
        raise credentials_exception
    USER = username
    return user

@app.get('/')
def show_owner():
    return{"18219005 - Gilbert Christian Sinaga"}

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user['username']}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

def isCustomer(User = Depends(get_current_user)):
    if USER != 'customer':
        # sys.exit()
        return()

def isAdmin(User = Depends(isCustomer())):
    return()

@app.get('/customer')
async def customer(User = Depends(isCustomer)):
    return("customer page successfully loaded")

@app.get('/admin')
async def admin(User = Depends(isAdmin)):
    return("admin page successfully loaded")

@app.post('/user/register')
async def register(username: str, password: str, User = Depends(isAdmin)):
    password = get_password_hash(password)
    new_user = {'username':username,'role':'admin', 'hashed_password':password, 'disabled':"False"}
    list_of_users['data'].append(dict(new_user))

    with open("user.json", "w") as write_file:
        json.dump(list_of_users,write_file,indent=4)
    return{"message": "Data added successfully"}
    write_file.close()
