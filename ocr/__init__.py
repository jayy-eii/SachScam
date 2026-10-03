"""
OCR Package for SachCheck.
Provides modular image preprocessing, OCR extraction, confidence scoring,
and visual evidence highlighting on chat screenshots.
"""

from ocr.models import OCRResult, OCRBox
from ocr.preprocessor import ImagePreprocessor, PreprocessedImage
from ocr.provider import BaseOCRProvider, EasyOCRProvider, MockOCRProvider
from ocr.service import OCRService, CATEGORY_COLOR_MAP
from ocr.structure import ChatStructureDetector, ChatMessage, ChatStructureReport

__all__ = [
    "OCRResult",
    "OCRBox",
    "ImagePreprocessor",
    "PreprocessedImage",
    "BaseOCRProvider",
    "EasyOCRProvider",
    "MockOCRProvider",
    "OCRService",
    "CATEGORY_COLOR_MAP",
    "ChatStructureDetector",
    "ChatMessage",
    "ChatStructureReport",
]
