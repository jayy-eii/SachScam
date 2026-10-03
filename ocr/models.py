"""
Data models for the OCR and visual evidence extraction pipeline.
Supports multi-language OCR bounding boxes, confidence scoring, and error handling.
"""

from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict, Any


@dataclass
class OCRBox:
    """Represents a single OCR text detection box with coordinates and confidence."""
    # Bounding box as 4 coordinates: [[x1, y1], [x2, y2], [x3, y3], [x4, y4]]
    bbox: List[List[int]]
    text: str
    confidence: float

    @property
    def x_min(self) -> int:
        return min(p[0] for p in self.bbox)

    @property
    def y_min(self) -> int:
        return min(p[1] for p in self.bbox)

    @property
    def x_max(self) -> int:
        return max(p[0] for p in self.bbox)

    @property
    def y_max(self) -> int:
        return max(p[1] for p in self.bbox)

    @property
    def width(self) -> int:
        return max(0, self.x_max - self.x_min)

    @property
    def height(self) -> int:
        return max(0, self.y_max - self.y_min)


@dataclass
class OCRResult:
    """Complete result returned by the OCR provider."""
    raw_text: str
    cleaned_text: str
    boxes: List[OCRBox] = field(default_factory=list)
    average_confidence: float = 0.0
    quality_score: int = 0  # 0 to 100
    quality_warning: Optional[str] = None
    is_successful: bool = True
    error_message: Optional[str] = None
    image_width: int = 0
    image_height: int = 0
    is_blurry: bool = False
    language_detected: str = "en"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cleaned_text": self.cleaned_text,
            "average_confidence": self.average_confidence,
            "quality_score": self.quality_score,
            "quality_warning": self.quality_warning,
            "is_successful": self.is_successful,
            "error_message": self.error_message,
            "box_count": len(self.boxes),
            "is_blurry": self.is_blurry,
            "language_detected": self.language_detected,
        }
