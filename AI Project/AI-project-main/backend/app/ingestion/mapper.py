from typing import List, Dict, Any, Optional
import uuid
from backend.app.models.core import ContentSpan, SourceType
from backend.app.config import settings

class ProvenanceMapper:
    """
    Responsible for mapping raw input requests into structured ContentSpans
    and assigning initial taint status based on source.
    """

    @staticmethod
    def map_request(request_data: Dict[str, Any]) -> List[ContentSpan]:
        """
        Converts a structured JSON request into a list of ContentSpans.

        Expected request_data format:
        {
            "system_instruction": str,
            "user_input": str,
            "external_data_blobs": [
                {"id": str, "source": str, "content": str},
                ...
            ],
            "tool_outputs": [
                {"id": str, "source": str, "content": str},
                ...
            ]
        }
        """
        spans = []

        # 1. Map System Instruction
        system_text = request_data.get("system_instruction")
        if system_text is not None:
            spans.append(ContentSpan(
                source=SourceType.SYSTEM,
                origin="system_config",
                original=system_text,
                tainted=False
            ))

        # 2. Map User Input
        user_text = request_data.get("user_input")
        if user_text is not None:
            spans.append(ContentSpan(
                source=SourceType.USER,
                origin="user_session",
                original=user_text,
                tainted=False
            ))

        # 3. Map External Data Blobs (Automatically Tainted)
        data_blobs = request_data.get("external_data_blobs", [])
        for blob in data_blobs:
            spans.append(ContentSpan(
                source=SourceType.DATA,
                origin=blob.get("source", "unknown_data_source"),
                original=blob.get("content", ""),
                tainted=True
            ))

        # 4. Map Tool Outputs (Automatically Tainted)
        tool_outputs = request_data.get("tool_outputs", [])
        for tool in tool_outputs:
            spans.append(ContentSpan(
                source=SourceType.TOOL,
                origin=tool.get("source", "unknown_tool"),
                original=tool.get("content", ""),
                tainted=True
            ))

        return spans

class IngestionPipeline:
    """
    The entry point for the firewall. Handles request ID generation
    and coordinates the mapping of input to spans.
    """

    def __init__(self, mapper: ProvenanceMapper):
        self.mapper = mapper

    def process(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        request_id = str(uuid.uuid4())
        try:
            spans = self.mapper.map_request(request_data)
            return {
                "request_id": request_id,
                "spans": spans,
                "status": "success"
            }
        except Exception as e:
            # Fail-closed: Any failure in ingestion results in a critical error
            return {
                "request_id": request_id,
                "status": "error",
                "error": str(e)
            }
