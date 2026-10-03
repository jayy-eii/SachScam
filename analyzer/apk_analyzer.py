"""
Safe, read-only static APK inspection module for SachCheck.

SECURITY GUARANTEES:
1. NEVER executes, installs, or runs uploaded or downloaded APK files.
2. Only inspects safe static metadata (SHA-256 hash, entry table, manifest presence).
3. Treats all uploaded files as untrusted data.
4. Strictly disclaims: "Static metadata extraction does not establish whether an APK
   contains malicious payloads. Only install apps from verified official app stores."
"""

import io
import zipfile
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Union


@dataclass
class APKInspectionResult:
    """Safe static metadata extracted from an untrusted APK archive."""
    is_valid_apk: bool
    file_size_bytes: int
    sha256_hash: str
    has_manifest: bool
    has_dex_code: bool
    has_resources: bool
    has_signing_cert: bool
    dex_count: int
    native_lib_architectures: List[str] = field(default_factory=list)
    archive_entries_count: int = 0
    package_name_hint: Optional[str] = None
    security_notice: str = (
        "Static metadata extraction inspected archive structure without execution. "
        "It does NOT establish malware safety. Third-party APKs downloaded outside official "
        "app stores pose significant device compromise and banking credential risks."
    )
    error_message: Optional[str] = None


class SafeAPKInspector:
    """Safely extracts static archive metadata from untrusted APK files without execution."""

    @classmethod
    def inspect(cls, file_input: Union[bytes, io.BytesIO, str]) -> APKInspectionResult:
        """
        Safely inspects an APK archive's structure and computes cryptographic hash.
        Never runs or installs the binary.
        """
        # Load raw bytes
        if isinstance(file_input, bytes):
            data = file_input
        elif isinstance(file_input, io.BytesIO):
            file_input.seek(0)
            data = file_input.read()
        elif isinstance(file_input, str):
            with open(file_input, "rb") as f:
                data = f.read()
        else:
            return APKInspectionResult(
                is_valid_apk=False,
                file_size_bytes=0,
                sha256_hash="",
                has_manifest=False,
                has_dex_code=False,
                has_resources=False,
                has_signing_cert=False,
                dex_count=0,
                error_message="Unsupported input type for APK inspection.",
            )

        file_size = len(data)
        if file_size == 0:
            return APKInspectionResult(
                is_valid_apk=False,
                file_size_bytes=0,
                sha256_hash="",
                has_manifest=False,
                has_dex_code=False,
                has_resources=False,
                has_signing_cert=False,
                dex_count=0,
                error_message="Uploaded file was empty.",
            )

        # 1. Compute SHA-256 hash
        sha256 = hashlib.sha256(data).hexdigest()

        # 2. Inspect ZIP archive structure
        try:
            stream = io.BytesIO(data)
            with zipfile.ZipFile(stream, "r") as z:
                namelist = z.namelist()
                entries_count = len(namelist)

                has_manifest = "AndroidManifest.xml" in namelist
                dex_files = [n for n in namelist if n.endswith(".dex")]
                has_resources = "resources.arsc" in namelist
                has_cert = any(n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC")) for n in namelist)

                # Detect native architectures in lib/
                archs = set()
                for n in namelist:
                    if n.startswith("lib/") and "/" in n[4:]:
                        arch = n.split("/")[1]
                        archs.add(arch)

                # Heuristic: Valid APK must have AndroidManifest.xml and classes.dex
                is_valid_apk = has_manifest and (len(dex_files) > 0)

                return APKInspectionResult(
                    is_valid_apk=is_valid_apk,
                    file_size_bytes=file_size,
                    sha256_hash=sha256,
                    has_manifest=has_manifest,
                    has_dex_code=len(dex_files) > 0,
                    has_resources=has_resources,
                    has_signing_cert=has_cert,
                    dex_count=len(dex_files),
                    native_lib_architectures=sorted(list(archs)),
                    archive_entries_count=entries_count,
                    error_message=None if is_valid_apk else "Archive does not exhibit standard Android package (APK) signatures.",
                )

        except zipfile.BadZipFile:
            return APKInspectionResult(
                is_valid_apk=False,
                file_size_bytes=file_size,
                sha256_hash=sha256,
                has_manifest=False,
                has_dex_code=False,
                has_resources=False,
                has_signing_cert=False,
                dex_count=0,
                error_message="Uploaded file is not a valid ZIP/APK archive.",
            )
        except Exception as e:
            return APKInspectionResult(
                is_valid_apk=False,
                file_size_bytes=file_size,
                sha256_hash=sha256,
                has_manifest=False,
                has_dex_code=False,
                has_resources=False,
                has_signing_cert=False,
                dex_count=0,
                error_message=f"Safe inspection error: {str(e)}",
            )
