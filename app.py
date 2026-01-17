from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jsonschema import validate, ValidationError
from typing import Any
import datetime, os, json, uuid, logging

# ----------------------------------------------------
# Athena CAP Bridge v2 – Production Hardened
# ----------------------------------------------------

# Setup structured logging
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO
)

app = FastAPI(title="Athena CAP Bridge v2", version="2.2")

# Enable CORS for external relays and GitHub workflows
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with specific domains for tighter security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------------------------------
# CAP Payload model (light validation pre-schema)
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
# Helper – Load CAP Schema
# ----------------------------------------------------
def load_cap_schema():
    """Safely load the canonical CAP schema."""
    schema_path = os.path.join(os.getcwd(), "schemas", "ATHENA_CAP_SCHEMA_v3_5.json")
    try:
        with open(schema_path, "r") as f:
            schema = json.load(f)
        logging.info(f"CAP schema loaded successfully from {schema_path}")
        return schema
    except FileNotFoundError:
        logging.error(f"Schema file not found at {schema_path}")
        raise HTTPException(status_code=500, detail="CAP schema missing from server.")
    except json.JSONDecodeError:
        logging.error(f"Schema file is not valid JSON.")
        raise HTTPException(status_code=500, detail="Invalid CAP schema JSON.")


CAP_SCHEMA = load_cap_schema()


# ----------------------------------------------------
# Health Endpoints
# ----------------------------------------------------
@app.get("/")
def root():
    """Default landing route."""
    return {"status": "alive", "time": datetime.datetime.utcnow().isoformat()}


@app.get("/healthz")
def healthz():
    """Used by Render or CI to verify uptime."""
    return {
        "service": "Athena CAP Bridge v2",
        "status": "healthy",
        "time": datetime.datetime.utcnow().isoformat()
    }


# ----------------------------------------------------
# CAP Intake Endpoint
# ----------------------------------------------------
@app.post("/cap")
async def receive_cap(request: Request):
    trace_id = str(uuid.uuid4())

    try:
        # Parse the incoming payload
        data = await request.json()
        logging.info(f"[TRACE {trace_id}] CAP received: {data.get('cap_id', 'unknown')}")

        # Step 1: Pydantic-level field validation
        payload = CAPPayload(**data)

        # Step 2: Schema-level validation (deep structure check)
        try:
            validate(instance=data, schema=CAP_SCHEMA)
        except ValidationError as ve:
            logging.warning(f"[TRACE {trace_id}] CAP schema validation failed: {ve.message}")
            raise HTTPException(status_code=422, detail=f"CAP schema validation error: {ve.message}")

        # Step 3: Log relay success
        bridge_url = os.getenv("BRIDGE_URL", "local")
        logging.info(f"[TRACE {trace_id}] CAP validated successfully → ready for relay ({bridge_url})")

        # Optional: Forward or store CAP (stub)
        return {
            "status": "CAP validated",
            "trace_id": trace_id,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "relay_target": bridge_url
        }

    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"[TRACE {trace_id}] CAP processing error: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid CAP payload: {str(e)}")


# ----------------------------------------------------
# Global Error Handler
# ----------------------------------------------------
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Consistent JSON error responses with trace IDs."""
    return {
        "error": True,
        "code": exc.status_code,
        "message": exc.detail,
        "trace_id": str(uuid.uuid4())
    }
