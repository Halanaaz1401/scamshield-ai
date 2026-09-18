"""External service integration adapters."""

from backend.src.services.bedrock_service import (
    BedrockAnalysisResult,
    analyze_with_bedrock,
    build_user_prompt,
    get_bedrock_config,
)
from backend.src.services.risk_fusion import (
    calibrate_risk_level,
    compute_fused_risk_score,
    fuse_risk_analysis,
    reconcile_category,
)
from backend.src.services.storage_service import (
    build_sanitized_record,
    get_storage_config,
    persist_analysis_record,
)

__all__ = [
    "analyze_with_bedrock",
    "BedrockAnalysisResult",
    "build_user_prompt",
    "get_bedrock_config",
    "compute_fused_risk_score",
    "calibrate_risk_level",
    "reconcile_category",
    "fuse_risk_analysis",
    "persist_analysis_record",
    "build_sanitized_record",
    "get_storage_config",
]