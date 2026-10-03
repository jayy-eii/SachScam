"""
Image preprocessing module for the SachCheck OCR pipeline.
Handles format validation (PNG, JPG, JPEG, WEBP), image normalization,
contrast adjustment, and blur/quality assessment.
"""

import io
from dataclasses import dataclass
from typing import Union, Tuple, Optional
from PIL import Image, ImageOps, ImageEnhance
import numpy as np
import cv2


SUPPORTED_FORMATS = {"PNG", "JPEG", "JPG", "WEBP"}
MIN_OPTIMAL_WIDTH = 900
BLUR_THRESHOLD = 50.0  # Laplacian variance below this is flagged as blurry


@dataclass
class PreprocessedImage:
    """Holds processed image data along with diagnostic image properties."""
    pil_image: Image.Image
    np_image: np.ndarray
    original_format: str
    width: int
    height: int
    blur_score: float
    is_blurry: bool
    scale_factor: float = 1.0


class ImagePreprocessor:
    """Preprocesses chat screenshots for optimal OCR text recognition."""

    @classmethod
    def load_and_preprocess(
        cls, image_input: Union[str, bytes, io.BytesIO, Image.Image]
    ) -> PreprocessedImage:
        """
        Loads and prepares an image for OCR.
        
        Args:
            image_input: File path, byte stream, or PIL Image object.
            
        Returns:
            PreprocessedImage with normalized PIL image and numpy array.
            
        Raises:
            ValueError: If the image format is unsupported or corrupted.
        """
        # 1. Load image
        if isinstance(image_input, Image.Image):
            pil_img = image_input
            fmt = pil_img.format or "PNG"
        elif isinstance(image_input, (bytes, bytearray)):
            stream = io.BytesIO(image_input)
            pil_img = Image.open(stream)
            fmt = pil_img.format or "PNG"
        elif isinstance(image_input, io.BytesIO):
            image_input.seek(0)
            pil_img = Image.open(image_input)
            fmt = pil_img.format or "PNG"
        elif isinstance(image_input, str):
            pil_img = Image.open(image_input)
            fmt = pil_img.format or "PNG"
        else:
            raise ValueError(f"Unsupported image input type: {type(image_input)}")

        fmt_upper = fmt.upper()
        if fmt_upper not in SUPPORTED_FORMATS:
            # Attempt to still read if standard RGB format
            if pil_img.format is None and pil_img.mode in ("RGB", "RGBA", "L"):
                fmt_upper = "PNG"
            else:
                raise ValueError(
                    f"Unsupported image format: {fmt_upper}. SachCheck supports PNG, JPG, JPEG, and WEBP."
                )

        # 2. Fix orientation using EXIF tags if present
        try:
            pil_img = ImageOps.exif_transpose(pil_img)
        except Exception:
            pass

        # 3. Convert RGBA / Grayscale to standard RGB
        if pil_img.mode != "RGB":
            # For RGBA, composite on white background rather than dropping alpha
            if pil_img.mode in ("RGBA", "LA") or (pil_img.mode == "P" and "transparency" in pil_img.info):
                alpha_img = pil_img.convert("RGBA")
                background = Image.new("RGB", alpha_img.size, (255, 255, 255))
                background.paste(alpha_img, mask=alpha_img.split()[3])
                pil_img = background
            else:
                pil_img = pil_img.convert("RGB")

        orig_w, orig_h = pil_img.size

        # 4. Check resolution and scale up if screenshot is small
        scale_factor = 1.0
        if orig_w < MIN_OPTIMAL_WIDTH:
            scale_factor = MIN_OPTIMAL_WIDTH / float(orig_w)
            new_w = MIN_OPTIMAL_WIDTH
            new_h = int(orig_h * scale_factor)
            pil_img = pil_img.resize((new_w, new_h), Image.Resampling.BICUBIC)

        # 5. Measure blur with OpenCV Laplacian variance
        np_arr = np.array(pil_img)
        gray = cv2.cvtColor(np_arr, cv2.COLOR_RGB2GRAY)
        laplacian_var = float(cv2.Laplacian(gray, cv2.CV_64F).var())
        is_blurry = laplacian_var < BLUR_THRESHOLD

        # 6. Moderate contrast enhancement for crisp chat bubbles
        enhancer = ImageEnhance.Contrast(pil_img)
        enhanced_pil = enhancer.enhance(1.15)
        sharpener = ImageEnhance.Sharpness(enhanced_pil)
        final_pil = sharpener.enhance(1.10)
        final_np = np.array(final_pil)

        return PreprocessedImage(
            pil_image=final_pil,
            np_image=final_np,
            original_format=fmt_upper,
            width=orig_w,
            height=orig_h,
            blur_score=round(laplacian_var, 2),
            is_blurry=is_blurry,
            scale_factor=scale_factor,
        )
