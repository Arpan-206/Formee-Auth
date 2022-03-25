from gql import Client, gql
from gql.transport.aiohttp import AIOHTTPTransport
import jwt
from typing import Optional
from dotenv import load_dotenv
from gql.transport.exceptions import TransportQueryError
from fastapi import FastAPI, Header, HTTPException
import os
load_dotenv()
app = FastAPI(
    title="CLI Wiki Auth API",
    description="CLI Wiki Auth API",
    version="0.1.0",
)


@app.get("/")
async def root(username: Optional[str] = Header(None), password: Optional[str] = Header(None)):
    # Execute the query on the transport
    if username is None or password is None:
        raise HTTPException(
            status_code=400, detail="Missing username or password")

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

    auth_jwt_data = {
        "sub": "1234567890",
        "name": "Auth",
        "admin": False,
        "iat": 1516239022,
        "https://hasura.io/jwt/claims": {
            "x-hasura-allowed-roles": ["user"],
            "x-hasura-default-role": "user",
            "x-hasura-user-id": "1234567890",
        }
    }

    auth_encoded_jwt = jwt.encode(
        auth_jwt_data, jwt_key, algorithm=jwt_algorithm)

    # Select your transport with a defined url endpoint
    transport = AIOHTTPTransport(url=hasura_graphql_url,
                                 headers={"Authorization": "Bearer {}".format(auth_encoded_jwt)})

    # Create a GraphQL client using the defined transport
    client = Client(transport=transport, fetch_schema_from_transport=True)

    # Provide a GraphQL query
    auth_query = gql(
        """
    query CheckUser($username: String!, $password: String!) {
    cliWiki_User(where: {_and: {password: {_eq: $password}, username: {_eq: $username}}}) {
        username
        password
        joined_on
        id
        bio
    }
    }

    """
    )
    result = await client.execute_async(auth_query, variable_values={"username": username, "password": password})
    result = result["cliWiki_User"]

    if len(result) > 0:
        user_jwt_data = {
            "sub": result[0]["id"],
            "name": username,
            "admin": False,
            "iat": 1516239022,
            "https://hasura.io/jwt/claims": {
                "x-hasura-allowed-roles": ["user"],
                "x-hasura-default-role": "user",
                "x-hasura-user-id": result[0]["id"],
            }
        }
        return {"jwt": jwt.encode(user_jwt_data, jwt_key, algorithm=jwt_algorithm)}

    return HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/signup")
async def signup(username: Optional[str] = Header(None), password: Optional[str] = Header(None)):
    # Execute the query on the transport
    if username is None or password is None:
        raise HTTPException(
            status_code=400, detail="Missing username or password")

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

    auth_jwt_data = {
        "sub": "1234567890",
        "name": "Auth",
        "admin": False,
        "iat": 1516239022,
        "https://hasura.io/jwt/claims": {
            "x-hasura-allowed-roles": ["user"],
            "x-hasura-default-role": "user",
            "x-hasura-user-id": "1234567890",
        }
    }

    auth_encoded_jwt = jwt.encode(
        auth_jwt_data, jwt_key, algorithm=jwt_algorithm)

    # Select your transport with a defined url endpoint
    transport = AIOHTTPTransport(url=hasura_graphql_url,
                                 headers={"Authorization": "Bearer {}".format(auth_encoded_jwt)})

    # Create a GraphQL client using the defined transport
    client = Client(transport=transport, fetch_schema_from_transport=True)

    # Provide a GraphQL query
    auth_query = gql(
        """
    mutation CreateUser($password: String!, $username: String!) {
  insert_cliWiki_User(objects: {username: $username, password: $password}) {
    returning {
      id
      username
      password
      joined_on
    }
  }
}

    """
    )
    try:
        result = await client.execute_async(auth_query, variable_values={"username": username, "password": password})
    except TransportQueryError:
        return HTTPException(status_code=400, detail="Username already exists")

    return result