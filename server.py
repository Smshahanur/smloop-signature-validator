
import os
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.settings import KeyUsageConstraints
from pyhanko_certvalidator import ValidationContext

app = FastAPI(title="SMLOOP PDF Signature Validator")

allowed_origins = [
    x.strip() for x in os.getenv("ALLOWED_ORIGINS", "*").split(",") if x.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False if "*" in allowed_origins else True,
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["*"],
)

MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", str(25 * 1024 * 1024)))

def iso(value):
    if value is None:
        return None
    try:
        return value.isoformat()
    except Exception:
        return str(value)

def text(value):
    if value is None:
        return None
    return str(value)

@app.get("/health")
def health():
    return {"ok": True, "service": "SMLOOP PDF Signature Validator"}

@app.post("/api/validate-pdf-signature")
async def validate_pdf_signature_endpoint(file: UploadFile = File(...)):
    filename = file.filename or "document.pdf"
    if not filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Please upload a PDF file.")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="PDF is too large.")
    if not content.startswith(b"%PDF-"):
        raise HTTPException(status_code=400, detail="The uploaded file does not appear to be a valid PDF.")

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        with open(tmp_path, "rb") as inf:
            reader = PdfFileReader(inf)
            embedded = list(reader.embedded_signatures)

            if not embedded:
                return {
                    "overall_status": "no_signature",
                    "signature_count": 0,
                    "document_modified_after_signing": "Unknown",
                    "message": "No embedded digital signature was found in this PDF.",
                    "signatures": [],
                }

            vc = ValidationContext(allow_fetching=True)
            signatures: List[Dict[str, Any]] = []

            for sig in embedded:
                try:
                    status = validate_pdf_signature(sig, signer_validation_context=vc)

                    intact = bool(getattr(status, "intact", False))
                    valid = bool(getattr(status, "valid", False))
                    trusted = bool(getattr(status, "trusted", False))

                    if intact and valid and trusted:
                        state = "valid"
                    elif not intact or not valid:
                        state = "invalid"
                    else:
                        state = "unknown"

                    signer_info = getattr(status, "signing_cert", None)
                    signer_name = None
                    certificate_issuer = None
                    certificate_expiry = None

                    if signer_info is not None:
                        try:
                            signer_name = signer_info.subject.human_friendly
                        except Exception:
                            signer_name = text(getattr(signer_info, "subject", None))
                        try:
                            certificate_issuer = signer_info.issuer.human_friendly
                        except Exception:
                            certificate_issuer = text(getattr(signer_info, "issuer", None))
                        try:
                            certificate_expiry = iso(signer_info.not_valid_after)
                        except Exception:
                            certificate_expiry = None

                    signing_time = None
                    try:
                        signing_time = iso(status.timestamp_validity.timestamp)
                    except Exception:
                        try:
                            signing_time = iso(getattr(status, "signing_time", None))
                        except Exception:
                            pass

                    modification_level = text(getattr(status, "modification_level", None))
                    modified = "Unknown"
                    if modification_level:
                        low = modification_level.lower()
                        if "none" in low or "lta_updates" in low:
                            modified = "No"
                        elif "other" in low or "form" in low or "annotation" in low:
                            modified = "Yes"

                    reason_parts = []
                    if not intact:
                        reason_parts.append("The signed byte ranges did not validate as intact.")
                    if intact and valid and not trusted:
                        reason_parts.append("The signature is cryptographically valid, but certificate trust could not be fully established.")
                    if not valid:
                        reason_parts.append("The signature or certificate validation did not pass.")

                    signatures.append({
                        "status": state,
                        "signer_name": signer_name or "Not available",
                        "signing_time": signing_time or "Not available",
                        "certificate_issuer": certificate_issuer or "Not available",
                        "certificate_expiry": certificate_expiry or "Not available",
                        "certificate_status": "Trusted" if trusted else ("Untrusted" if valid else "Invalid"),
                        "modified_after_signing": modified,
                        "reason": " ".join(reason_parts) or "Validation completed.",
                    })
                except Exception as exc:
                    signatures.append({
                        "status": "unknown",
                        "signer_name": "Not available",
                        "signing_time": "Not available",
                        "certificate_issuer": "Not available",
                        "certificate_expiry": "Not available",
                        "certificate_status": "Unknown",
                        "modified_after_signing": "Unknown",
                        "reason": f"Could not fully validate this signature: {exc}",
                    })

            states = [s["status"] for s in signatures]
            if any(s == "invalid" for s in states):
                overall = "invalid"
            elif signatures and all(s == "valid" for s in states):
                overall = "valid"
            else:
                overall = "unknown"

            modified_values = {s["modified_after_signing"] for s in signatures}
            if "Yes" in modified_values:
                document_modified = "Yes"
            elif modified_values == {"No"}:
                document_modified = "No"
            else:
                document_modified = "Unknown"

            return {
                "overall_status": overall,
                "signature_count": len(signatures),
                "document_modified_after_signing": document_modified,
                "message": "Cryptographic PDF signature validation completed.",
                "signatures": signatures,
            }

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Could not process this PDF: {exc}"
        )
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
