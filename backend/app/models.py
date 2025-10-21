from pydantic import BaseModel
from typing import Optional

class AnalysisRequest(BaseModel):
    input_data: str

class EmailAnalysisResponse(BaseModel):
    email: str
    is_valid_syntax: bool
    domain: str
    has_mx_records: bool

class UrlAnalysisResponse(BaseModel):
    url: str
    domain: str
    domain_age_days: Optional[int]
    registrar: Optional[str]
    virustotal_analysis: dict