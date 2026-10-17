import os
import json
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional

SARVAM_API_URL = "https://api.sarvam.ai/v1/chat/completions"


def call_sarvam_chat(
    messages: List[Dict[str, str]],
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    timeout: int = 15,
) -> Dict[str, Any]:
    """Call Sarvam Chat Completions API with the given messages.
    
    Returns raw JSON dictionary response or raises an exception.
    """
    key = api_key or os.getenv("SARVAM_API_KEY")
    if not key:
        raise ValueError("SARVAM_API_KEY environment variable is not configured")

    selected_model = model or os.getenv("SARVAM_MODEL", "sarvam-105b-conversations")

    headers = {
        "api-subscription-key": key,
        "Content-Type": "application/json",
    }
    payload = {
        "model": selected_model,
        "messages": messages,
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(SARVAM_API_URL, data=data, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            res_body = response.read().decode("utf-8")
            return json.loads(res_body)
    except urllib.error.HTTPError as e:
        error_msg = e.read().decode("utf-8")
        raise RuntimeError(f"Sarvam API HTTP error {e.code}: {error_msg}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Sarvam API network error: {e.reason}") from e
    except Exception as e:
        raise RuntimeError(f"Sarvam API request failed: {str(e)}") from e
