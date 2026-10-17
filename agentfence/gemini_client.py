import os
from typing import Optional
from google import genai

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def get_gemini_client(api_key: Optional[str] = None) -> genai.Client:
    """Create and return a configured Google GenAI client."""
    key = api_key or os.getenv("GEMINI_API_KEY")
    if not key:
        raise ValueError("GEMINI_API_KEY environment variable is not configured")
    return genai.Client(api_key=key)


def get_gemini_model() -> str:
    """Return the configured Gemini model ID (defaults to gemini-3.8-flash)."""
    return os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
