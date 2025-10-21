from fastapi import FastAPI
from .models import AnalysisRequest, UrlAnalysisResponse, EmailAnalysisResponse
from . import services

app = FastAPI(title="VeriSpector API")

@app.get("/")
def read_root():
    return {"status": "API is running"}

@app.post("/analyze/url", response_model=UrlAnalysisResponse)
async def analyze_url_endpoint(request: AnalysisRequest):
    analysis_result = await services.perform_url_analysis(request.input_data)
    return analysis_result

@app.post("/analyze/email", response_model=EmailAnalysisResponse)
async def analyze_email_endpoint(request: AnalysisRequest):
    analysis_result = await services.perform_email_analysis(request.input_data)
    return analysis_result