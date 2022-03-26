import jwt
from typing import Optional
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import requests
import os
load_dotenv()
app = FastAPI(
    title="Formee Auth API",
    description="Formee Auth API",
    version="0.1.0",
)


class User(BaseModel):
    id: Optional[int]
    avatar_url: Optional[str]
    created_on: Optional[str]
    email: Optional[str]
    bio: Optional[str]
    username: str
    password: str


jwt_key = os.getenv("JWT_KEY")
jwt_algorithm = os.getenv("JWT_ALGORITHM")
hasura_graphql_url = os.getenv("HASURA_GRAPHQL_ENDPOINT_URL")
if jwt_key is None:
    raise HTTPException(
        status_code=500, detail="Missing JWT key in .env")
if jwt_algorithm is None:
    raise HTTPException(
        status_code=500, detail="Missing JWT algorithm in .env")
if hasura_graphql_url is None:
    raise HTTPException(
        status_code=500, detail="Missing Hasura GraphQL URL in .env")


@app.get("/")
async def root(user: User):
    # Execute the query on the transport
    username = user.username
    password = user.password
    # if user.id:
    #     user_id = str(user.id)
    # else:
    #     user_id = str(randint(1, 100))
    if username is None or password is None:
        raise HTTPException(
            status_code=400, detail="Missing username or password")

    url = 'https://hrbt-portal.hasura.app/api/rest/user/'
    headers = {'Content-Type': 'application/json',
               'x-hasura-admin-secret': os.environ['HASURA_ACCESS_TOKEN']}
    body = {'username': username, 'password': password}
    response = requests.get(url, headers=headers, json=body).json()
    if len(response['User']) == 0:
        raise HTTPException(
            status_code=400, detail="Invalid username or password")
    user_id = response['User'][0]['id']
    auth_jwt_data = {
        "sub": user_id,
        "name": username,
        "admin": False,
        "iat": 1516239022,
        "https://hasura.io/jwt/claims": {
            "x-hasura-allowed-roles": ["user"],
            "x-hasura-default-role": "user",
            "x-hasura-user-id": user_id,
            "x-hasura-username": username
        }
    }

    auth_encoded_jwt = jwt.encode(
        auth_jwt_data, jwt_key, algorithm=jwt_algorithm)
    return {"token": auth_encoded_jwt}


@app.get("/visitor")
async def visitor():
    auth_jwt_data = {
        "sub": "123456",
        "name": "Visitor",
        "admin": False,
        "iat": 1516239022,
        "https://hasura.io/jwt/claims": {
            "x-hasura-allowed-roles": ["visitor"],
            "x-hasura-default-role": "visitor",
            "x-hasura-user-id": "123456",
        }
    }

    auth_encoded_jwt = jwt.encode(
        auth_jwt_data, jwt_key, algorithm=jwt_algorithm)
    return {"token": auth_encoded_jwt}
