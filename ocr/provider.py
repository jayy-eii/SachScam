"""
Modular OCR provider implementation for SachCheck.
Allows EasyOCR, PaddleOCR, or mock providers to be used interchangeably.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Tuple, Dict, Any
import logging
import numpy as np

from ocr.models import OCRBox, OCRResult

logger = logging.getLogger(__name__)


class BaseOCRProvider(ABC):
    """Abstract interface for all OCR providers."""

    @abstractmethod
    def extract_text(self, np_image: np.ndarray) -> OCRResult:
        """
        Extract text and bounding boxes from a numpy RGB image.
        
        Args:
            np_image: RGB image represented as a numpy array.
            
        Returns:
            OCRResult object with bounding boxes and confidence scores.
        """
        pass


class EasyOCRProvider(BaseOCRProvider):
    """
    Concrete OCR provider powered by EasyOCR.
    Supports English ('en') and Hindi ('hi') text extraction with confidence scores.
    """

    def __init__(self, languages: Optional[List[str]] = None, use_gpu: bool = False):
        self.languages = languages or ["en", "hi"]
        self.use_gpu = use_gpu
        self._reader = None

    def _get_reader(self):
        """Lazy initialization of EasyOCR Reader to conserve resources."""
        if self._reader is None:
            try:
                import easyocr
                # Initialize reader with English and Hindi
                self._reader = easyocr.Reader(self.languages, gpu=self.use_gpu)
            except Exception as e:
                logger.error(f"Failed to initialize EasyOCR reader: {e}")
                raise RuntimeError(f"EasyOCR initialization failed: {e}")
        return self._reader

    def extract_text(self, np_image: np.ndarray) -> OCRResult:
        """Execute OCR extraction using EasyOCR."""
        if np_image is None or np_image.size == 0:
            return OCRResult(
                raw_text="",
                cleaned_text="",
                boxes=[],
                average_confidence=0.0,
                quality_score=0,
                quality_warning="Image data was empty or unreadable.",
                is_successful=False,
                error_message="Text could not be reliably extracted",
            )

        h, w = np_image.shape[:2]

        try:
            reader = self._get_reader()
            # EasyOCR returns list of tuples: (bbox, text, confidence)
            # bbox is [[x1, y1], [x2, y2], [x3, y3], [x4, y4]]
            raw_detections = reader.readtext(np_image)
        except Exception as e:
            logger.error(f"EasyOCR extraction error: {e}")
            return OCRResult(
                raw_text="",
                cleaned_text="",
                boxes=[],
                average_confidence=0.0,
                quality_score=0,
                quality_warning=f"OCR engine encountered an error: {str(e)}",
                is_successful=False,
                error_message="Text could not be reliably extracted",
                image_width=w,
                image_height=h,
            )

        if not raw_detections:
            return OCRResult(
                raw_text="",
                cleaned_text="",
                boxes=[],
                average_confidence=0.0,
                quality_score=0,
                quality_warning="No visible text detected in this image.",
                is_successful=False,
                error_message="Text could not be reliably extracted",
                image_width=w,
                image_height=h,
            )

        boxes: List[OCRBox] = []
        text_lines: List[str] = []
        confidences: List[float] = []

        # Sort detections primarily top-to-bottom, secondarily left-to-right (natural reading order)
        # Using minimum y coordinate for sorting
        sorted_detections = sorted(
            raw_detections,
            key=lambda item: (min(pt[1] for pt in item[0]), min(pt[0] for pt in item[0]))
        )

        for bbox, text, conf in sorted_detections:
            text_str = str(text).strip()
            if not text_str:
                continue

            conf_val = float(conf) if conf is not None else 0.5
            confidences.append(conf_val)
            text_lines.append(text_str)

            # Ensure bbox coordinates are integers
            int_bbox = [[int(pt[0]), int(pt[1])] for pt in bbox]
            boxes.append(OCRBox(bbox=int_bbox, text=text_str, confidence=round(conf_val, 3)))

        if not text_lines:
            return OCRResult(
                raw_text="",
                cleaned_text="",
                boxes=[],
                average_confidence=0.0,
                quality_score=0,
                quality_warning="No text lines could be recognized from the image.",
                is_successful=False,
                error_message="Text could not be reliably extracted",
                image_width=w,
                image_height=h,
            )

        avg_conf = sum(confidences) / len(confidences) if confidences else 0.0
        quality_score = int(round(avg_conf * 100))

        # Check for quality warning threshold (< 60% confidence)
        quality_warning = None
        if quality_score < 60:
            quality_warning = (
                "Some text in this screenshot may not have been recognized correctly. "
                "Review the extracted text before relying on the analysis."
            )

        raw_text = "\n".join(text_lines)
        cleaned_text = raw_text

        # Detect primary script (Devanagari vs Latin)
        has_devanagari = any('\u0900' <= char <= '\u097F' for char in cleaned_text)
        lang_detected = "hi" if has_devanagari else "en"

        return OCRResult(
            raw_text=raw_text,
            cleaned_text=cleaned_text,
            boxes=boxes,
            average_confidence=round(avg_conf, 3),
            quality_score=quality_score,
            quality_warning=quality_warning,
            is_successful=True,
            error_message=None,
            image_width=w,
            image_height=h,
            language_detected=lang_detected,
        )


class MockOCRProvider(BaseOCRProvider):
    """
    Mock OCR provider for deterministic unit testing.
    Can be configured to return specific text, simulated bounding boxes, or failures.
    """

    def __init__(
        self,
        mock_text: str = "",
        confidence: float = 0.90,
        should_fail: bool = False,
        mock_boxes: Optional[List[OCRBox]] = None,
    ):
        self.mock_text = mock_text
        self.confidence = confidence
        self.should_fail = should_fail
        self.mock_boxes = mock_boxes or []

    def extract_text(self, np_image: np.ndarray) -> OCRResult:
        if self.should_fail or not self.mock_text.strip():
            return OCRResult(
                raw_text="",
                cleaned_text="",
                boxes=[],
                average_confidence=0.0,
                quality_score=0,
                quality_warning="Simulated extraction failure.",
                is_successful=False,
                error_message="Text could not be reliably extracted",
            )

        lines = [line.strip() for line in self.mock_text.split("\n") if line.strip()]
        boxes = self.mock_boxes
        if not boxes:
            # Generate realistic synthetic boxes
            boxes = [
                OCRBox(
                    bbox=[[10, i * 40], [300, i * 40], [300, (i + 1) * 40], [10, (i + 1) * 40]],
                    text=line,
                    confidence=self.confidence,
                )
                for i, line in enumerate(lines)
            ]

        quality_score = int(round(self.confidence * 100))
        warning = None
        if quality_score < 60:
            warning = (
                "Some text in this screenshot may not have been recognized correctly. "
                "Review the extracted text before relying on the analysis."
            )

        return OCRResult(
            raw_text=self.mock_text,
            cleaned_text=self.mock_text,
            boxes=boxes,
            average_confidence=round(self.confidence, 3),
            quality_score=quality_score,
            quality_warning=warning,
            is_successful=True,
            error_message=None,
        )
