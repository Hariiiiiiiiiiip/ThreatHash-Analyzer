import os
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = FastAPI(title="ThreatHash API")

# Configure CORS so React (running on a different port) can communicate with FastAPI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exactly e.g. ["http://localhost:5173"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

VT_API_KEY = os.getenv("VT_API_KEY")
VT_API_URL = "https://www.virustotal.com/api/v3/files"

@app.get("/api/scan/{file_hash}")
async def scan_hash(file_hash: str):
    if not VT_API_KEY:
        raise HTTPException(status_code=500, detail="VT_API_KEY is not configured in .env")

    headers = {
        "x-apikey": VT_API_KEY
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{VT_API_URL}/{file_hash}", headers=headers)
            
            if response.status_code == 404:
                # Hash not found in VirusTotal
                return build_empty_report(file_hash)
            elif response.status_code == 401 or response.status_code == 403:
                raise HTTPException(status_code=401, detail="Invalid VirusTotal API Key")
            
            response.raise_for_status()
            data = response.json()
            
            return parse_vt_response(file_hash, data)

    except httpx.RequestError as exc:
        raise HTTPException(status_code=503, detail=f"Error connecting to VirusTotal: {str(exc)}")

def build_empty_report(file_hash: str):
    return {
        "sha256": file_hash,
        "detectionRatio": "0/72",
        "riskScore": "Safe",
        "severity": "safe",
        "malwareFamily": "None",
        "threatLabels": "None",
        "scanStatus": "Clean",
        "engineResults": []
    }

def parse_vt_response(file_hash: str, vt_data: dict):
    attributes = vt_data.get("data", {}).get("attributes", {})
    
    stats = attributes.get("last_analysis_stats", {})
    malicious_count = stats.get("malicious", 0)
    suspicious_count = stats.get("suspicious", 0)
    total_count = sum(stats.values())
    
    # Calculate Risk Score and Severity
    total_detections = malicious_count + suspicious_count
    
    if total_detections >= 15:
        risk_score = "Malware"
        severity = "malware"
        scan_status = "Malicious"
    elif total_detections >= 6:
        risk_score = "Dangerous"
        severity = "dangerous"
        scan_status = "Suspicious"
    elif total_detections >= 1:
        risk_score = "Suspicious"
        severity = "suspicious"
        scan_status = "Suspicious"
    else:
        risk_score = "Safe"
        severity = "safe"
        scan_status = "Clean"
        
    # Extract popular threat labels
    popular_threat_categories = attributes.get("popular_threat_classification", {}).get("popular_threat_category", [])
    threat_labels = ", ".join([cat.get("value") for cat in popular_threat_categories]) if popular_threat_categories else "None"
    
    # Try to extract a meaningful malware family name
    suggested_threat_label = attributes.get("popular_threat_classification", {}).get("suggested_threat_label", "Unknown")
    
    # Engine Results
    results = attributes.get("last_analysis_results", {})
    engine_results = []
    
    # We'll pull a subset of known engines for the UI if they exist, or just all that detected something
    for engine_name, result_data in results.items():
        if result_data.get("category") in ["malicious", "suspicious"]:
            engine_results.append({
                "name": engine_name,
                "result": result_data.get("result", "Unsafe"),
                "isMalicious": True
            })
            
    # Add a few clean ones just for UI representation if we have less than 12
    for engine_name, result_data in results.items():
        if len(engine_results) >= 12:
            break
        if result_data.get("category") == "undetected":
            engine_results.append({
                "name": engine_name,
                "result": "Undetected",
                "isMalicious": False
            })

    return {
        "sha256": file_hash,
        "detectionRatio": f"{total_detections}/{total_count if total_count > 0 else 72}",
        "riskScore": risk_score,
        "severity": severity,
        "malwareFamily": suggested_threat_label if total_detections > 0 else "None",
        "threatLabels": threat_labels,
        "scanStatus": scan_status,
        "engineResults": engine_results
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
