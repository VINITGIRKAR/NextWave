from typing import List, Optional, Dict
from pydantic import BaseModel

class User(BaseModel):
    uid: int
    name: str
    mail: str = None
    permissions: List[Dict]
    user_roles: List[Dict]

class UpdateLastSequenceData(BaseModel):
    state: int = None
    city: int = None
    operator: int = None
    batch_id: int = None
    images: List[Dict] = None


