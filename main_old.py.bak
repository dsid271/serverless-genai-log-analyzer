import os
from typing import List, Dict, Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import PromptTemplate
import markdown

# Load environment variables (this is fine for local testing, but remember to configure them on Render)
load_dotenv()
# Try both GEMINI_API_KEY and GOOGLE_API_KEY for compatibility
gemini_api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")

if not gemini_api_key:
    # This will prevent the app from starting if the key is missing
    raise ValueError("Google API key not set. Please set GEMINI_API_KEY or GOOGLE_API_KEY as an environment variable.")

# Initialize the FastAPI app instance
# In a production environment like Render, this 'app' instance is directly imported
# and served by the platform's web server (e.g., Gunicorn or Uvicorn).
app = FastAPI(title="Serverless GenAI Log Analyzer")
llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash", google_api_key=gemini_api_key)

class LogEntry(BaseModel):
    log_data: Dict[str, Any]

class LogAnalysisRequest(BaseModel):
    logs: List[LogEntry]

prompt_template = PromptTemplate.from_template(
    "You are an expert network analyst. Analyze the following network logs to "
    "identify any potential issues, anomalies, or security threats. "
    "Summarize your findings, and provide key insights. "
    "Here are the network logs:\n\n{logs_json}"
)

# Added a root endpoint to test if the server is alive
@app.get("/")
async def root():
    return {"message": "Serverless GenAI Log Analyzer is running!"}

@app.post("/analyze-log", tags=["Log Analysis"])
async def analyze_log(request: LogAnalysisRequest):
    """
    Accepts a list of network logs and returns an AI-generated analysis.
    """
    if not request.logs:
        raise HTTPException(status_code=400, detail="No log entries provided.")

    try:
        logs_json = [log.log_data for log in request.logs]
        formatted_prompt = prompt_template.format(logs_json=logs_json)
        response = llm.invoke(formatted_prompt)
        html_content = markdown.markdown(response.content)
        return {
            "status": "success",
            "analysis": response.content,
            "analysis_html": html_content,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))