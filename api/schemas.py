"""
SirenUA API Request and Response Schemas.
Declares Pydantic validation models for threat simulation and uploads.
"""

from pydantic import BaseModel
from typing import Optional, List

class ThreatSetRequest(BaseModel):
    region: str
    level: str  # none, low, medium, high, critical
    threat_type: Optional[str] = None
    detail: Optional[str] = None


class ShelterUploadItem(BaseModel):
    name: Optional[str] = None
    address: Optional[str] = None
    lat: float
    lon: float
    type: str = "bomb_shelter"
    capacity: Optional[int] = None
    accessible: bool = False


class ShelterUploadRequest(BaseModel):
    shelters: List[ShelterUploadItem]


class ScenarioRequest(BaseModel):
    scenario: str  # mig_takeoff, shaheds_south, cruise_missiles_west, massive_attack, ballistic_kharkiv


class TelegramTestRequest(BaseModel):
    text: str
    channel: str = "kpszsu"
