from fastapi import Security, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from typing import Dict, List

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Mock user database for demonstration of secure role-based auth
# In a real environment, this would hit the DBUser table
MOCK_USERS = {
    "token-analyst": {"username": "analyst1", "role": "ANALYST", "permissions": ["view", "investigate"]},
    "token-responder": {"username": "responder1", "role": "RESPONDER", "permissions": ["view", "investigate", "approve"]},
    "token-admin": {"username": "admin1", "role": "ADMIN", "permissions": ["view", "investigate", "approve", "configure"]}
}

async def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict:
    user = MOCK_USERS.get(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

def require_role(allowed_roles: List[str]):
    def role_checker(user: Dict = Depends(get_current_user)):
        if user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted"
            )
        return user
    return role_checker
