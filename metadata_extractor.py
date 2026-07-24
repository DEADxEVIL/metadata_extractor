import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, Any, List
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import exifread
import piexif
import numpy as np
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut
import filetype
from datetime import datetime


class ExtractionError(Exception):
    """Base exception for extraction errors."""
    pass


@dataclass
class FileInfo:
    filename: str
    size_bytes: int
    size_mb: float
    format: str
    mime_type: str
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    magic_bytes: Optional[str] = None
    created_timestamp: Optional[str] = None
    modified_timestamp: Optional[str] = None
    accessed_timestamp: Optional[str] = None
    file_extension: Optional[str] = None
    signature_analysis: Optional[Dict[str, Any]] = field(default_factory=dict)


@dataclass
class ExifData:
    camera_make: Optional[str] = None
    camera_model: Optional[str] = None
    camera_serial: Optional[str] = None
    lens_make: Optional[str] = None
    lens_model: Optional[str] = None
    lens_focal_length: Optional[str] = None
    datetime_original: Optional[str] = None
    datetime_digitized: Optional[str] = None
    datetime_modified: Optional[str] = None
    exposure_time: Optional[str] = None
    f_number: Optional[str] = None
    iso: Optional[int] = None
    focal_length: Optional[str] = None
    focal_length_35mm: Optional[str] = None
    flash: Optional[str] = None
    white_balance: Optional[str] = None
    metering_mode: Optional[str] = None
    exposure_mode: Optional[str] = None
    scene_capture_type: Optional[str] = None
    software: Optional[str] = None
    orientation: Optional[str] = None
    color_space: Optional[str] = None
    sensing_method: Optional[str] = None
    user_comment: Optional[str] = None


@dataclass
class GPSData:
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude: Optional[float] = None
    timestamp: Optional[str] = None
    img_direction: Optional[float] = None
    gps_track: Optional[float] = None
    speed: Optional[float] = None
    satellites: Optional[int] = None
    satellite_count: Optional[int] = None
    processing_method: Optional[str] = None
    address: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None


@dataclass
class ImageProperties:
    width: int
    height: int
    color_mode: str
    bit_depth: Optional[int] = None
    dpi: Optional[tuple] = None
    compression: Optional[str] = None
    format_description: Optional[str] = None
    channels: Optional[int] = None
    has_alpha: bool = False
    color_histogram: Optional[Dict[str, Any]] = field(default_factory=dict)
    pixel_range: Optional[Dict[str, Any]] = field(default_factory=dict)


@dataclass
class DeviceInfo:
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    device_id: Optional[str] = None
    unique_id: Optional[str] = None
    firmware: Optional[str] = None
    hardware_version: Optional[str] = None
    software_version: Optional[str] = None
    build_info: Optional[Dict[str, Any]] = field(default_factory=dict)


@dataclass
class ExtractionResult:
    file_info: Optional[FileInfo] = None
    exif_data: Optional[ExifData] = None
    gps_data: Optional[GPSData] = None
    image_properties: Optional[ImageProperties] = None
    device_info: Optional[DeviceInfo] = None
    hidden_data: Optional[Dict[str, Any]] = field(default_factory=dict)
    anomalies: List[str] = field(default_factory=list)
    extraction_timestamp: Optional[str] = None
    raw_exif: Optional[Dict[str, Any]] = field(default_factory=dict)
    xmp_data: Optional[Dict[str, Any]] = field(default_factory=dict)
    iptc_data: Optional[Dict[str, Any]] = field(default_factory=dict)


class ForensicMetadataExtractor:
    """Main metadata extraction engine - optimized for speed."""

    def __init__(self):
        self.geocoder = Nominatim(user_agent="forensic_extractor_v4", timeout=3)

    def extract_metadata(
        self,
        file_path: Path | str,
        original_filename: Optional[str] = None,
        enable_gps: bool = True,
    ) -> ExtractionResult:
        """Extract all metadata from an image file."""
        file_path = Path(file_path)

        if not file_path.exists():
            raise ExtractionError(f"File not found: {file_path}")

        print(f"[EXTRACTOR] Starting: {file_path.name} ({file_path.stat().st_size} bytes)", flush=True)

        try:
            result = ExtractionResult()
            result.extraction_timestamp = datetime.now().isoformat()

            # File info
            result.file_info = self._extract_file_info(file_path, original_filename)

            # Open image
            with Image.open(file_path) as img:
                # Image properties
                result.image_properties = self._extract_image_properties(img)

                # EXIF
                try:
                    result.exif_data, result.raw_exif = self._extract_exif_data(img, file_path)
                    print(f"[EXTRACTOR] EXIF: {len(result.raw_exif)} tags, date={result.exif_data.datetime_original}", flush=True)
                except Exception as e:
                    print(f"[EXTRACTOR] EXIF error: {e}", flush=True)
                    result.exif_data = ExifData()
                    result.raw_exif = {}

                # If no EXIF date, use file modification time
                if result.exif_data and not result.exif_data.datetime_original:
                    try:
                        mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                        result.exif_data.datetime_modified = mtime.strftime('%Y:%m:%d %H:%M:%S')
                    except Exception:
                        pass

                # GPS
                try:
                    result.gps_data = self._extract_gps_data(img, file_path, enable_gps)
                except Exception as e:
                    print(f"[EXTRACTOR] GPS error: {e}", flush=True)
                    result.gps_data = None

                # Hidden data
                try:
                    result.hidden_data = self._extract_hidden_data(img, file_path)
                except Exception:
                    result.hidden_data = {}

                # Device info
                result.device_info = self._extract_device_info(result.exif_data)

                # XMP
                try:
                    result.xmp_data = self._extract_xmp_data(img)
                except Exception:
                    result.xmp_data = {}

            # Anomalies
            result.anomalies = self._detect_anomalies(result)
            print(f"[EXTRACTOR] Complete! Anomalies: {result.anomalies}", flush=True)
            return result

        except Exception as e:
            raise ExtractionError(f"Unexpected error: {str(e)}")

    def _extract_file_info(self, file_path: Path, original_filename: Optional[str] = None) -> FileInfo:
        """Extract file-level information."""
        stat = file_path.stat()

        kind = filetype.guess(str(file_path))
        if kind is not None:
            mime_type = kind.mime
            format_name = kind.extension
        else:
            try:
                with Image.open(file_path) as img:
                    format_name = img.format.lower() if img.format else "unknown"
                mime_type = f"image/{format_name}"
            except Exception:
                format_name = file_path.suffix.lower().lstrip(".") or "unknown"
                mime_type = f"image/{format_name}"

        md5 = self._calculate_hash(file_path, "md5")
        sha1 = self._calculate_hash(file_path, "sha1")
        sha256 = self._calculate_hash(file_path, "sha256")
        magic_bytes = self._read_magic_bytes(file_path)

        created_ts = datetime.fromtimestamp(stat.st_ctime).isoformat()
        modified_ts = datetime.fromtimestamp(stat.st_mtime).isoformat()
        accessed_ts = datetime.fromtimestamp(stat.st_atime).isoformat()

        return FileInfo(
            filename=original_filename or file_path.name,
            size_bytes=stat.st_size,
            size_mb=stat.st_size / (1024 * 1024),
            format=format_name.upper() if format_name else "UNKNOWN",
            mime_type=mime_type,
            md5=md5, sha1=sha1, sha256=sha256,
            magic_bytes=magic_bytes,
            created_timestamp=created_ts,
            modified_timestamp=modified_ts,
            accessed_timestamp=accessed_ts,
            file_extension=file_path.suffix.lower(),
            signature_analysis=self._analyze_signature(file_path, magic_bytes),
        )

    def _extract_image_properties(self, img: Image.Image) -> ImageProperties:
        """Extract image properties."""
        width, height = img.size
        color_mode = img.mode
        dpi = img.info.get("dpi", None)
        compression = str(img.info.get("compression", "")) or None

        bit_depth_map = {"1": 1, "L": 8, "P": 8, "RGB": 24, "RGBA": 32, "CMYK": 32}
        bit_depth = bit_depth_map.get(color_mode, None)

        channel_map = {"RGB": 3, "RGBA": 4, "CMYK": 4, "LA": 2, "PA": 2, "1": 1, "L": 1, "P": 1}
        channels = channel_map.get(color_mode, 1)

        return ImageProperties(
            width=width, height=height, color_mode=color_mode,
            bit_depth=bit_depth, dpi=dpi, compression=compression,
            format_description=img.format or "unknown",
            channels=channels, has_alpha=color_mode in ("RGBA", "LA", "PA"),
        )

    def _extract_exif_data(self, img: Image.Image, file_path: Path) -> tuple[Optional[ExifData], Dict[str, Any]]:
        """Extract EXIF with comprehensive date/time handling."""
        exif_data = ExifData()
        raw_exif = {}

        # METHOD 1: PIL (fast)
        try:
            exif_dict = img.getexif()
            if exif_dict and len(exif_dict) > 0:
                # First pass: get all raw tags
                for tag_id, value in exif_dict.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))
                    try:
                        val_str = str(value)
                    except Exception:
                        val_str = "unprintable"
                    raw_exif[tag_name] = val_str

                # Second pass: map to our fields
                for tag_id, value in exif_dict.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))
                    try:
                        val_str = str(value).strip()
                    except Exception:
                        continue

                    # Camera
                    if tag_name == "Make":
                        exif_data.camera_make = val_str
                    elif tag_name == "Model":
                        exif_data.camera_model = val_str

                    # Date/Time - try multiple fields
                    elif tag_name == "DateTimeOriginal":
                        exif_data.datetime_original = val_str
                    elif tag_name == "DateTimeDigitized":
                        exif_data.datetime_digitized = val_str
                    elif tag_name == "DateTime":
                        if not exif_data.datetime_original:
                            exif_data.datetime_original = val_str
                        exif_data.datetime_modified = val_str

                    # Timezone offset
                    elif tag_name in ("OffsetTime", "OffsetTimeOriginal", "OffsetTimeDigitized"):
                        if exif_data.datetime_original and not exif_data.datetime_original.endswith(val_str):
                            exif_data.datetime_original += val_str

                    elif tag_name == "Software":
                        exif_data.software = val_str
                    elif tag_name in ("ISOSpeedRatings", "ISO"):
                        try:
                            exif_data.iso = int(float(str(value)))
                        except (ValueError, TypeError):
                            pass
                    elif tag_name == "FNumber":
                        try:
                            exif_data.f_number = f"{float(value):.1f}"
                        except Exception:
                            exif_data.f_number = val_str
                    elif tag_name == "ExposureTime":
                        exif_data.exposure_time = val_str
                    elif tag_name == "FocalLength":
                        try:
                            exif_data.focal_length = f"{float(value):.1f}"
                        except Exception:
                            exif_data.focal_length = val_str
                    elif tag_name == "FocalLengthIn35mmFilm":
                        exif_data.focal_length_35mm = val_str
                    elif tag_name == "Flash":
                        exif_data.flash = val_str
                    elif tag_name == "WhiteBalance":
                        exif_data.white_balance = val_str
                    elif tag_name == "MeteringMode":
                        exif_data.metering_mode = val_str
                    elif tag_name == "LensModel":
                        exif_data.lens_model = val_str
                    elif tag_name == "LensMake":
                        exif_data.lens_make = val_str
                    elif tag_name == "Orientation":
                        exif_data.orientation = val_str
                    elif tag_name == "ColorSpace":
                        exif_data.color_space = val_str
                    elif tag_name in ("BodySerialNumber", "CameraSerialNumber"):
                        exif_data.camera_serial = val_str
                    elif tag_name == "ExposureMode":
                        exif_data.exposure_mode = val_str
                    elif tag_name == "SceneCaptureType":
                        exif_data.scene_capture_type = val_str
                    elif tag_name == "UserComment":
                        exif_data.user_comment = val_str

                # Also try SubIFD for DateTimeOriginal
                if not exif_data.datetime_original:
                    try:
                        if 34665 in exif_dict:  # ExifIFD tag
                            sub_ifd = exif_dict.get_ifd(34665)
                            if sub_ifd:
                                for sub_id, sub_val in sub_ifd.items():
                                    sub_name = TAGS.get(sub_id, str(sub_id))
                                    if sub_name == "DateTimeOriginal":
                                        exif_data.datetime_original = str(sub_val).strip()
                                        raw_exif["DateTimeOriginal"] = str(sub_val).strip()
                                        break
                    except Exception:
                        pass

                if len(raw_exif) > 0:
                    return exif_data, raw_exif
        except Exception as e:
            print(f"[EXIF] PIL failed: {e}", flush=True)

        # METHOD 2: exifread (only for files under 30MB)
        file_size = file_path.stat().st_size
        if file_size < 30 * 1024 * 1024:
            try:
                with open(file_path, "rb") as f:
                    tags = exifread.process_file(f, details=False, stop_tag="UndefinedTag")
                    for tag, value in tags.items():
                        tag_str = str(tag).strip()
                        val_str = str(value).strip()
                        raw_exif[tag_str] = val_str

                        if tag_str == "Image Make":
                            exif_data.camera_make = val_str
                        elif tag_str == "Image Model":
                            exif_data.camera_model = val_str
                        elif tag_str == "EXIF DateTimeOriginal":
                            exif_data.datetime_original = val_str
                        elif tag_str == "EXIF DateTimeDigitized":
                            exif_data.datetime_digitized = val_str
                        elif tag_str == "Image DateTime":
                            if not exif_data.datetime_original:
                                exif_data.datetime_original = val_str
                            else:
                                exif_data.datetime_modified = val_str
                        elif tag_str == "EXIF LensModel":
                            exif_data.lens_model = val_str
                        elif tag_str == "EXIF LensMake":
                            exif_data.lens_make = val_str
                        elif tag_str == "EXIF ExposureTime":
                            exif_data.exposure_time = val_str
                        elif tag_str == "EXIF FNumber":
                            exif_data.f_number = val_str
                        elif tag_str == "EXIF ISOSpeedRatings":
                            try:
                                exif_data.iso = int(float(val_str))
                            except (ValueError, TypeError):
                                pass
                        elif tag_str == "EXIF FocalLength":
                            exif_data.focal_length = val_str
                        elif tag_str == "EXIF FocalLengthIn35mmFilm":
                            exif_data.focal_length_35mm = val_str
                        elif tag_str == "EXIF Flash":
                            exif_data.flash = val_str
                        elif tag_str == "EXIF WhiteBalance":
                            exif_data.white_balance = val_str
                        elif tag_str == "Image Software":
                            exif_data.software = val_str
                        elif tag_str == "Image Orientation":
                            exif_data.orientation = val_str
                        elif tag_str in ("EXIF BodySerialNumber", "Image BodySerialNumber"):
                            exif_data.camera_serial = val_str
                        elif tag_str == "EXIF OffsetTime" or tag_str == "EXIF OffsetTimeOriginal":
                            if exif_data.datetime_original and val_str:
                                exif_data.datetime_original += val_str
            except Exception as e:
                print(f"[EXIF] exifread failed: {e}", flush=True)

        return exif_data, raw_exif

    def _extract_gps_data(self, img: Image.Image, file_path: Path, enable_gps: bool = True) -> Optional[GPSData]:
        """Extract GPS data."""
        gps_data = GPSData()
        has_gps = False

        # Try PIL GPS IFD
        try:
            exif_dict = img.getexif()
            if 34853 in exif_dict:
                gps_info = exif_dict.get_ifd(34853)
                if gps_info:
                    lat, lat_ref, lon, lon_ref = None, None, None, None
                    gps_time = None
                    gps_date = None

                    for tag_id, value in gps_info.items():
                        tag_name = GPSTAGS.get(tag_id, str(tag_id))
                        if tag_name == "GPSLatitude":
                            lat = self._convert_gps_coord(value)
                        elif tag_name == "GPSLatitudeRef":
                            lat_ref = str(value).strip()
                        elif tag_name == "GPSLongitude":
                            lon = self._convert_gps_coord(value)
                        elif tag_name == "GPSLongitudeRef":
                            lon_ref = str(value).strip()
                        elif tag_name == "GPSAltitude":
                            try:
                                gps_data.altitude = float(value)
                            except (ValueError, TypeError):
                                pass
                        elif tag_name == "GPSTimeStamp":
                            gps_time = str(value)
                        elif tag_name == "GPSDateStamp":
                            gps_date = str(value)
                        elif tag_name == "GPSImgDirection":
                            try:
                                gps_data.img_direction = float(value)
                            except (ValueError, TypeError):
                                pass
                        elif tag_name == "GPSSatellites":
                            try:
                                gps_data.satellite_count = int(str(value))
                            except (ValueError, TypeError):
                                pass
                        elif tag_name == "GPSSpeed":
                            try:
                                gps_data.speed = float(value)
                            except (ValueError, TypeError):
                                pass

                    # Combine GPS date and time
                    if gps_date and gps_time:
                        gps_data.timestamp = f"{gps_date} {gps_time}"
                    elif gps_date:
                        gps_data.timestamp = gps_date
                    elif gps_time:
                        gps_data.timestamp = gps_time

                    if lat is not None and lon is not None:
                        if lat_ref == "S":
                            lat = -lat
                        if lon_ref == "W":
                            lon = -lon
                        gps_data.latitude = lat
                        gps_data.longitude = lon
                        has_gps = True
        except Exception:
            pass

        # Fallback: exifread
        if not has_gps and file_path.stat().st_size < 30 * 1024 * 1024:
            try:
                with open(file_path, "rb") as f:
                    tags = exifread.process_file(f, details=False, stop_tag="UndefinedTag")
                    lat, lat_ref, lon, lon_ref = None, None, None, None
                    gps_time, gps_date = None, None

                    for tag, value in tags.items():
                        tag_str = str(tag).strip()
                        if tag_str == "GPS GPSLatitude":
                            lat = self._parse_gps_rational(str(value))
                        elif tag_str == "GPS GPSLatitudeRef":
                            lat_ref = str(value).strip()
                        elif tag_str == "GPS GPSLongitude":
                            lon = self._parse_gps_rational(str(value))
                        elif tag_str == "GPS GPSLongitudeRef":
                            lon_ref = str(value).strip()
                        elif tag_str == "GPS GPSTimeStamp":
                            gps_time = str(value)
                        elif tag_str == "GPS GPSDateStamp":
                            gps_date = str(value)

                    if gps_date and gps_time:
                        gps_data.timestamp = f"{gps_date} {gps_time}"
                    elif gps_date:
                        gps_data.timestamp = gps_date
                    elif gps_time:
                        gps_data.timestamp = gps_time

                    if lat is not None and lon is not None:
                        if lat_ref == "S":
                            lat = -lat
                        if lon_ref == "W":
                            lon = -lon
                        gps_data.latitude = lat
                        gps_data.longitude = lon
                        has_gps = True
            except Exception:
                pass

        # Geocode
        if has_gps and enable_gps and gps_data.latitude and gps_data.longitude:
            try:
                location = self.geocoder.reverse(
                    f"{gps_data.latitude}, {gps_data.longitude}",
                    language="en", timeout=3
                )
                if location:
                    gps_data.address = location.address
                    addr = location.raw.get("address", {})
                    gps_data.city = addr.get("city") or addr.get("town") or addr.get("village")
                    gps_data.country = addr.get("country")
            except Exception:
                pass

        return gps_data if has_gps else None

    def _extract_hidden_data(self, img: Image.Image, file_path: Path) -> Dict[str, Any]:
        """Extract hidden data."""
        hidden = {}
        try:
            exif_dict = piexif.load(str(file_path))
            thumbnail = exif_dict.get("thumbnail")
            if thumbnail and len(thumbnail) > 0:
                hidden["has_thumbnail"] = True
                hidden["thumbnail_size_bytes"] = len(thumbnail)
        except Exception:
            pass
        try:
            if "xmp" in img.info:
                hidden["has_xmp"] = True
        except Exception:
            pass
        try:
            if "icc_profile" in img.info:
                hidden["has_icc_profile"] = True
        except Exception:
            pass
        return hidden

    def _extract_xmp_data(self, img: Image.Image) -> Dict[str, Any]:
        try:
            if "xmp" in img.info:
                return {"raw": str(img.info["xmp"])}
        except Exception:
            pass
        return {}

    def _extract_device_info(self, exif_data: Optional[ExifData]) -> Optional[DeviceInfo]:
        if not exif_data:
            return None
        d = DeviceInfo()
        if exif_data.camera_make:
            d.manufacturer = exif_data.camera_make
        if exif_data.camera_model:
            d.model = exif_data.camera_model
        if exif_data.camera_serial:
            d.unique_id = exif_data.camera_serial
        if exif_data.software:
            d.software_version = exif_data.software
        return d if (d.manufacturer or d.model) else None

    def _detect_anomalies(self, result: ExtractionResult) -> List[str]:
        anomalies = []
        if not result.file_info:
            return anomalies

        actual = result.file_info.format.lower() if result.file_info.format else ""
        claimed = result.file_info.file_extension.lower().lstrip(".") if result.file_info.file_extension else ""

        if actual and claimed:
            format_map = {
                "jpeg": ["jpg", "jpeg", "jpe", "jfif"],
                "png": ["png"], "gif": ["gif"], "bmp": ["bmp", "dib"],
                "tiff": ["tiff", "tif"], "webp": ["webp"],
            }
            matched = False
            for fmt, exts in format_map.items():
                if actual in exts and claimed in exts:
                    matched = True
                    break
                elif actual == fmt and claimed in exts:
                    matched = True
                    break
            if not matched and actual != claimed:
                anomalies.append(f"Extension (.{claimed}) doesn't match format ({actual})")

        # Check if this looks like a screenshot or downloaded image
        if result.file_info.format.upper() in ("JPEG", "PNG", "TIFF"):
            if result.exif_data:
                if not result.exif_data.camera_make and not result.exif_data.datetime_original:
                    if not result.exif_data.software:
                        anomalies.append("No EXIF camera data - possible screenshot or downloaded image")
            else:
                anomalies.append("No EXIF data found - image metadata has been stripped")

        if result.image_properties:
            if result.image_properties.width < 200 or result.image_properties.height < 200:
                anomalies.append("Very small image (possible thumbnail or icon)")

        return anomalies

    @staticmethod
    def _calculate_hash(file_path: Path, algorithm: str) -> str:
        h = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _read_magic_bytes(file_path: Path, num_bytes: int = 16) -> str:
        try:
            with open(file_path, "rb") as f:
                return " ".join(f"{b:02x}" for b in f.read(num_bytes))
        except Exception:
            return ""

    @staticmethod
    def _analyze_signature(file_path: Path, magic_bytes: str) -> Dict[str, Any]:
        analysis = {"valid": True, "warnings": []}
        magic_hex = magic_bytes.replace(" ", "").lower()
        sigs = {
            "ffd8ffe0": "JPEG (JFIF)", "ffd8ffe1": "JPEG (EXIF)", "ffd8ffe2": "JPEG (Canon)",
            "89504e47": "PNG", "47494638": "GIF", "424d": "BMP",
            "49492a00": "TIFF (Intel)", "4d4d002a": "TIFF (Motorola)",
            "52494646": "RIFF (WebP/AVI)", "0000000c6a502020": "JPEG 2000",
        }
        for sig, name in sigs.items():
            if magic_hex.startswith(sig):
                analysis["signature"] = name
                return analysis
        analysis["valid"] = False
        analysis["warnings"].append("Unrecognized signature")
        return analysis

    @staticmethod
    def _convert_gps_coord(coord_tuple) -> float:
        """Convert GPS coordinate - handles IFDRational safely."""
        try:
            if hasattr(coord_tuple, 'numerator') and hasattr(coord_tuple, 'denominator'):
                return float(coord_tuple.numerator) / float(coord_tuple.denominator)
            if isinstance(coord_tuple, (tuple, list)) and len(coord_tuple) == 3:
                values = []
                for v in coord_tuple:
                    if hasattr(v, 'numerator') and hasattr(v, 'denominator'):
                        values.append(float(v.numerator) / float(v.denominator))
                    else:
                        values.append(float(v))
                return values[0] + values[1]/60.0 + values[2]/3600.0
            return float(coord_tuple)
        except Exception:
            return 0.0

    @staticmethod
    def _parse_gps_rational(gps_str: str) -> float:
        """Parse GPS rational string safely."""
        try:
            parts = gps_str.strip("[]").split(",")
            total = 0.0
            for i, part in enumerate(parts[:3]):
                part = part.strip()
                if "/" in part:
                    num, den = part.split("/")
                    val = float(num) / float(den) if float(den) != 0 else 0.0
                else:
                    val = float(part)
                if i == 0:
                    total += val
                elif i == 1:
                    total += val / 60.0
                elif i == 2:
                    total += val / 3600.0
            return total
        except Exception:
            return 0.0
