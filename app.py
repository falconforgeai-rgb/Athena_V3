from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jsonschema import validate, ValidationError
from typing import Any
import datetime, os, json, uuid, logging, requests

# ----------------------------------------------------
# Athena CAP Bridge v2 – Autonomous Relay
# ----------------------------------------------------

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO
)

app = FastAPI(title="Athena CAP Bridge v2", version="2.3")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # restrict later if needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------------------------------
# CAP Payload model
# ----------------------------------------------------
class CAPPayload(BaseModel):
    cap_id: str
    timestamp: str
    domain: str
    context_mode: str
    advisor_of_record: str
    outputs: Any
    cap_extensions: Any
    integrity: Any

# ----------------------------------------------------
# Helper: Load Schema
# ----------------------------------------------------
def load_cap_schema():
    schema_path = os.path.join(os.getcwd(), "schemas", "ATHENA_CAP_SCHEMA_v3_5.json")
    try:
        with open(schema_path, "r") as f:
            schema = json.load(f)
        logging.info(f"CAP schema loaded successfully from {schema_path}")
        return schema
    except Exception as e:
        logging.error(f"Failed to load CAP schema: {e}")
        raise HTTPException(status_code=500, detail="CAP schema missing or invalid.")

CAP_SCHEMA = load_cap_schema()

# ----------------------------------------------------
# Health Routes
# ----------------------------------------------------
@app.get("/")
def root():
    return {"status": "alive", "time": datetime.datetime.utcnow().isoformat()}

@app.get("/healthz")
def healthz():
    return {
        "service": "Athena CAP Bridge v2",
        "status": "healthy",
        "time": datetime.datetime.utcnow().isoformat()
    }

# ----------------------------------------------------
# Relay Helper
# ----------------------------------------------------
def relay_cap_payload(data: dict, trace_id: str):
    """Send validated CAP payload to configured bridge relay."""
    bridge_url = os.getenv("BRIDGE_URL", "")
    token = os.getenv("RENDER_API_TOKEN", "")

    if not bridge_url:
        logging.warning(f"[TRACE {trace_id}] No BRIDGE_URL set — skipping relay.")
        return {"relay": "skipped", "reason": "BRIDGE_URL not set"}

    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        response = requests.post(f"{bridge_url}/cap", headers=headers, json=data, timeout=10)
        if response.status_code == 200:
            logging.info(f"[TRACE {trace_id}] CAP relay succeeded to {bridge_url}")
            return {"relay": "success", "bridge_status": response.json()}
        else:
            logging.warning(f"[TRACE {trace_id}] CAP relay failed: {response.status_code}")
            return {"relay": "failed", "code": response.status_code, "body": response.text}
    except Exception as e:
        logging.error(f"[TRACE {trace_id}] CAP relay exception: {e}")
        return {"relay": "error", "message": str(e)}

# ----------------------------------------------------
# CAP Intake + Validation + Relay
# ----------------------------------------------------
@app.post("/cap")
async def receive_cap(request: Request):
    trace_id = str(uuid.uuid4())

    try:
        data = await request.json()
        logging.info(f"[TRACE {trace_id}] CAP received: {data.get('cap_id', 'unknown')}")

        # Step 1: Field-level validation
        payload = CAPPayload(**data)

        # Step 2: Schema validation
        try:
            validate(instance=data, schema=CAP_SCHEMA)
        except ValidationError as ve:
            logging.warning(f"[TRACE {trace_id}] Schema validation failed: {ve.message}")
            raise HTTPException(status_code=422, detail=f"CAP schema validation error: {ve.message}")

        # Step 3: Relay the payload
        relay_result = relay_cap_payload(data, trace_id)

        return {
            "status": "CAP validated",
            "trace_id": trace_id,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "relay_result": relay_result
        }

    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"[TRACE {trace_id}] CAP processing error: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid CAP payload: {str(e)}")

# ----------------------------------------------------
# Error Handler
# ----------------------------------------------------
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return {
        "error": True,
        "code": exc.status_code,
        "message": exc.detail,
        "trace_id": str(uuid.uuid4())
    }
