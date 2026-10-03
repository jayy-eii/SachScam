"""
OCR Service orchestrating image loading, preprocessing, OCR execution,
text cleaning, and visual evidence bounding-box annotation.
"""

from typing import Union, List, Tuple, Optional, Dict, Any
import io
import re
from PIL import Image, ImageDraw, ImageFont
import numpy as np

from ocr.models import OCRResult, OCRBox
from ocr.preprocessor import ImagePreprocessor, PreprocessedImage
from ocr.provider import BaseOCRProvider, EasyOCRProvider
from analyzer.models import DetectedIndicator


# Mapping category IDs to visual highlight colors (RGB & Hex)
CATEGORY_COLOR_MAP: Dict[str, Tuple[Tuple[int, int, int], str, str]] = {
    # category_id: (RGB tuple, Hex string, Emoji)
    "GUARANTEED_RETURN": ((239, 68, 68), "#EF4444", "🔴"),         # Red
    "PAYMENT_REQUEST": ((249, 115, 22), "#F97316", "🟠"),           # Orange
    "URGENCY_FOMO": ((234, 179, 8), "#EAB308", "🟡"),               # Yellow
    "AUTHORITY_IMPERSONATION": ((59, 130, 246), "#3B82F6", "🔵"),   # Blue
    "SUSPICIOUS_LINK": ((139, 92, 246), "#8B5CF6", "🟣"),          # Purple
    "APP_INSTALLATION": ((225, 29, 72), "#E11D48", "🛑"),           # Rose/Red
    "CREDENTIAL_REQUEST": ((190, 24, 93), "#BE185D", "⛔"),         # Crimson
    "WITHDRAWAL_FEE": ((217, 119, 6), "#D97706", "⚠️"),            # Amber
    "MANIPULATIVE_TRADING": ((217, 70, 239), "#D946EF", "🟣"),     # Fuchsia
    "EXTERNAL_GROUP": ((14, 165, 233), "#0EA5E9", "💬"),           # Sky Blue
    "FAKE_PROFIT": ((16, 185, 129), "#10B981", "📈"),               # Emerald
    "REFERRAL_PRESSURE": ((99, 102, 241), "#6366F1", "👥"),        # Indigo
    "INSTALL_REMOTE_APP": ((225, 29, 72), "#E11D48", "🖥️"),         # Rose / Screen
    "SHARE_REMOTE_SESSION_CODE": ((239, 68, 68), "#EF4444", "🔑"), # Red / Key
    "REMOTE_ACCESS_APP": ((168, 85, 247), "#A855F7", "🛡️"),        # Purple / Remote
}

DEFAULT_COLOR = ((100, 116, 139), "#64748B", "⚪")


class OCRService:
    """End-to-end OCR processing and visual highlighting service."""

    def __init__(self, provider: Optional[BaseOCRProvider] = None):
        self.provider = provider if provider is not None else EasyOCRProvider()

    def process_image(
        self, image_input: Union[str, bytes, io.BytesIO, Image.Image]
    ) -> Tuple[OCRResult, Image.Image]:
        """
        Execute full OCR pipeline on an uploaded screenshot.
        
        Args:
            image_input: Image file path, bytes, or PIL Image.
            
        Returns:
            Tuple of (OCRResult, normalized PIL Image).
        """
        try:
            preprocessed = ImagePreprocessor.load_and_preprocess(image_input)
        except Exception as e:
            return (
                OCRResult(
                    raw_text="",
                    cleaned_text="",
                    boxes=[],
                    average_confidence=0.0,
                    quality_score=0,
                    quality_warning=f"Image preprocessing failed: {str(e)}",
                    is_successful=False,
                    error_message="Text could not be reliably extracted",
                ),
                Image.new("RGB", (400, 200), (240, 240, 240)),
            )

        ocr_res = self.provider.extract_text(preprocessed.np_image)

        # Scale bounding box coordinates back to normalized PIL image scale if resized
        if preprocessed.scale_factor != 1.0 and ocr_res.boxes:
            inv_scale = 1.0  # Already relative to preprocessed.pil_image
            # Bounding boxes directly align with preprocessed.pil_image

        ocr_res.is_blurry = preprocessed.is_blurry
        if preprocessed.is_blurry and ocr_res.is_successful:
            if not ocr_res.quality_warning:
                ocr_res.quality_warning = (
                    "Screenshot appears low-resolution or blurry. "
                    "Some text may not have been recognized correctly. "
                    "Review the extracted text before relying on the analysis."
                )

        # Clean text
        ocr_res.cleaned_text = self.clean_ocr_text(ocr_res.raw_text)
        return ocr_res, preprocessed.pil_image

    @staticmethod
    def clean_ocr_text(text: str) -> str:
        """
        Cleans OCR text by standardizing line breaks and removing noisy whitespace.
        Preserves punctuation, emojis, and Hindi characters intact.
        """
        if not text:
            return ""

        # Normalize line endings
        cleaned = text.replace("\r\n", "\n").replace("\r", "\n")
        # Replace multiple spaces with single space within lines
        lines = [re.sub(r"[ \t]+", " ", line).strip() for line in cleaned.split("\n")]
        # Remove consecutive blank lines
        non_empty_lines = []
        for line in lines:
            if line or (non_empty_lines and non_empty_lines[-1] != ""):
                non_empty_lines.append(line)

        return "\n".join(non_empty_lines).strip()

    @classmethod
    def annotate_image(
        cls,
        pil_image: Image.Image,
        ocr_result: OCRResult,
        indicators: List[DetectedIndicator],
    ) -> Image.Image:
        """
        Draws visual evidence bounding boxes on the screenshot corresponding
        strictly to text matching detected risk indicators.
        
        NEVER invents or draws fake bounding boxes if no matching text was found by OCR.
        """
        if not ocr_result.boxes or not indicators or not ocr_result.is_successful:
            return pil_image.copy()

        annotated = pil_image.copy()
        draw = ImageDraw.Draw(annotated, "RGBA")

        # Load font for labels if available, otherwise default
        try:
            font = ImageFont.load_default()
        except Exception:
            font = None

        drawn_boxes_count = 0

        # Build search phrases for each indicator
        # Collect all phrases and categories
        for indicator in indicators:
            color_rgb, hex_color, emoji = CATEGORY_COLOR_MAP.get(
                indicator.category_id, DEFAULT_COLOR
            )
            # Semi-transparent overlay color
            overlay_color = (color_rgb[0], color_rgb[1], color_rgb[2], 50)
            border_color = (color_rgb[0], color_rgb[1], color_rgb[2], 230)

            for box in ocr_result.boxes:
                box_text_lower = box.text.lower().strip()
                if not box_text_lower or len(box_text_lower) < 2:
                    continue

                # Check if this box overlaps with any matched phrase in the indicator
                is_match = False
                matched_label = indicator.category

                for phrase in indicator.matched_phrases:
                    phrase_lower = phrase.lower().strip()
                    # Check substring match either way
                    if phrase_lower in box_text_lower or box_text_lower in phrase_lower:
                        is_match = True
                        break

                if is_match:
                    x_min, y_min = box.x_min, box.y_min
                    x_max, y_max = box.x_max, box.y_max

                    # Ensure coordinates are within image boundaries
                    x_min = max(0, x_min)
                    y_min = max(0, y_min)
                    x_max = min(pil_image.width, x_max)
                    y_max = min(pil_image.height, y_max)

                    # 1. Fill translucent box
                    draw.rectangle([x_min, y_min, x_max, y_max], fill=overlay_color)
                    # 2. Draw crisp bounding border
                    for offset in range(3):
                        draw.rectangle(
                            [x_min - offset, y_min - offset, x_max + offset, y_max + offset],
                            outline=border_color,
                        )

                    # 3. Draw category badge pill above box if space allows, otherwise inside
                    badge_text = f"{emoji} {matched_label}"
                    tag_y = max(0, y_min - 16) if y_min >= 16 else y_min
                    text_w = len(badge_text) * 7
                    draw.rectangle(
                        [x_min, tag_y, min(pil_image.width, x_min + text_w + 8), tag_y + 14],
                        fill=border_color,
                    )
                    draw.text((x_min + 4, tag_y + 1), badge_text, fill=(255, 255, 255), font=font)
                    drawn_boxes_count += 1

        return annotated
