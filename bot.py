import asyncio
import logging
import os
import json
import hashlib
import tempfile
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List, Set
from dataclasses import asdict
from enum import Enum

from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes,
    CallbackQueryHandler,
)
from telegram.error import BadRequest

from metadata_extractor import (
    ForensicMetadataExtractor,
    ExtractionResult,
    ExtractionError,
)
from logger_config import setup_logging, ForensicsLogger

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
AUTHORIZED_USERS_STR = os.getenv("AUTHORIZED_USERS", "")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "100"))
ENABLE_GPS_LOOKUP = os.getenv("ENABLE_GPS_LOOKUP", "true").lower() == "true"

AUTHORIZED_USERS: Set[int] = set()
if AUTHORIZED_USERS_STR:
    try:
        AUTHORIZED_USERS = set(int(uid.strip()) for uid in AUTHORIZED_USERS_STR.split(",") if uid.strip())
    except ValueError:
        logging.error("Invalid AUTHORIZED_USERS format in .env")

TEMP_DIR = Path(tempfile.gettempdir()) / "forensic_bot"
TEMP_DIR.mkdir(exist_ok=True)

EXTRACTION_TIMEOUT = 60


def safe_str(val) -> str:
    """Convert any value to string safely - handles IFDRational and other special types."""
    try:
        if val is None:
            return ""
        if hasattr(val, 'numerator') and hasattr(val, 'denominator'):
            return str(float(val))
        return str(val)
    except Exception:
        return "unknown"


class ForensicBot:
    """Main Telegram bot for forensic image analysis."""

    def __init__(self, token: str):
        self.token = token
        self.logger = ForensicsLogger("ForensicBot")
        self.extractor = ForensicMetadataExtractor()
        self.application: Optional[Application] = None
        self.stats = {
            "total_analyses": 0,
            "successful_analyses": 0,
            "failed_analyses": 0,
            "total_users": set(),
            "start_time": datetime.now(),
        }

    async def initialize(self) -> None:
        self.application = Application.builder().token(self.token).build()

        self.application.add_handler(CommandHandler("start", self.cmd_start))
        self.application.add_handler(CommandHandler("help", self.cmd_help))
        self.application.add_handler(CommandHandler("status", self.cmd_status))
        self.application.add_handler(CommandHandler("debug", self.cmd_debug))

        self.application.add_handler(MessageHandler(filters.PHOTO, self.handle_photo_warning))
        self.application.add_handler(MessageHandler(filters.Document.IMAGE, self.handle_image))
        self.application.add_handler(MessageHandler(filters.Document.ALL, self.handle_document))

        self.application.add_handler(CallbackQueryHandler(self.handle_export_callback))
        self.application.add_error_handler(self.error_handler)

        self.logger.log_info("Bot initialized")

    async def start(self) -> None:
        if not self.application:
            await self.initialize()
        await self.application.initialize()
        await self.application.start()
        await self.application.updater.start_polling(allowed_updates=Update.ALL_TYPES)

    async def stop(self) -> None:
        if self.application:
            await self.application.updater.stop()
            await self.application.stop()
            await self.application.shutdown()

    def _check_auth(self, user_id: int) -> bool:
        if not AUTHORIZED_USERS or user_id in AUTHORIZED_USERS:
            return True
        self.logger.log_security_event(user_id=user_id, action="UNAUTHORIZED", status="DENIED")
        return False

    async def _safe_edit(self, msg, text: str, parse_mode: str = "HTML") -> bool:
        try:
            await msg.edit_text(text, parse_mode=parse_mode)
            return True
        except (BadRequest, Exception):
            return False

    async def _safe_delete(self, msg) -> bool:
        try:
            await msg.delete()
            return True
        except (BadRequest, Exception):
            return False

    # =============================================
    # COMMANDS
    # =============================================

    async def cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not self._check_auth(update.effective_user.id):
            await update.message.reply_text("❌ Access Denied")
            return
        await update.message.reply_text(
            "🔍 <b>Forensic Image Metadata Extractor</b>\n\n"
            "⚠️ <b>SEND IMAGES AS FILES, NOT PHOTOS!</b>\n"
            "Telegram compresses photos and strips ALL metadata.\n\n"
            "<b>How to send correctly:</b>\n"
            "📱 Mobile: 📎 → <b>File</b> → select image\n"
            "💻 Desktop: 📎 → File → Browse\n\n"
            "<b>Commands:</b> /help /status /debug",
            parse_mode="HTML"
        )

    async def cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not self._check_auth(update.effective_user.id):
            return
        await update.message.reply_text(
            "📖 <b>Commands:</b>\n"
            "/start - Welcome\n/help - This message\n"
            "/status - Statistics\n/debug - Raw data view\n\n"
            "⚠️ Send images as <b>Files</b> only!",
            parse_mode="HTML"
        )

    async def cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not self._check_auth(update.effective_user.id):
            return
        uptime = datetime.now() - self.stats["start_time"]
        h, m = int(uptime.total_seconds() // 3600), int((uptime.total_seconds() % 3600) // 60)
        rate = 0
        if self.stats['total_analyses'] > 0:
            rate = (self.stats['successful_analyses'] / self.stats['total_analyses']) * 100
        await update.message.reply_text(
            f"📊 <b>Status</b>\n"
            f"✓ Online | Uptime: {h}h {m}m\n"
            f"Analyses: {self.stats['total_analyses']} ({rate:.0f}% success)\n"
            f"Max File: {MAX_FILE_SIZE_MB} MB",
            parse_mode="HTML"
        )

    async def cmd_debug(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not self._check_auth(update.effective_user.id):
            return
        result = context.user_data.get("last_result")
        if not result:
            await update.message.reply_text("❌ No data. Send an image file first.")
            return

        lines = ["🔧 <b>DEBUG</b>"]
        if result.file_info:
            fi = result.file_info
            lines.append(f"FILE: {fi.format} | {fi.size_mb:.2f}MB | {fi.mime_type}")
        if result.exif_data:
            ed = result.exif_data
            lines.append(f"EXIF: make='{safe_str(ed.camera_make)}' model='{safe_str(ed.camera_model)}'")
            lines.append(f"lens='{safe_str(ed.lens_model)}' date='{safe_str(ed.datetime_original)}'")
            lines.append(f"iso={safe_str(ed.iso)} f/{safe_str(ed.f_number)} {safe_str(ed.exposure_time)}s focal={safe_str(ed.focal_length)}mm")
            lines.append(f"flash='{safe_str(ed.flash)}' software='{safe_str(ed.software)}'")
        else:
            lines.append("EXIF: NONE")
        if result.gps_data:
            gps = result.gps_data
            lines.append(f"GPS: {safe_str(gps.latitude)}, {safe_str(gps.longitude)} | alt={safe_str(gps.altitude)}m")
            lines.append(f"addr={safe_str(gps.address)}")
        else:
            lines.append("GPS: NONE")
        lines.append(f"RAW TAGS: {len(result.raw_exif) if result.raw_exif else 0}")
        await update.message.reply_text("\n".join(lines), parse_mode="HTML")

    # =============================================
    # MESSAGE HANDLERS
    # =============================================

    async def handle_photo_warning(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not self._check_auth(update.effective_user.id):
            return
        await update.message.reply_text(
            "❌ <b>COMPRESSED PHOTO - NO METADATA!</b>\n\n"
            "Send as <b>FILE</b> instead:\n"
            "📱 📎 → <b>File</b> → select image\n"
            "💻 📎 → File → Browse",
            parse_mode="HTML"
        )

    async def handle_image(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Process image files with timeout protection."""
        user_id = update.effective_user.id
        if not self._check_auth(user_id):
            await update.message.reply_text("❌ Access Denied")
            return

        if not update.message.document:
            return

        file_obj = update.message.document
        if not file_obj.mime_type or not file_obj.mime_type.startswith("image/"):
            return

        original_filename = file_obj.file_name or f"image_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        if file_obj.file_size and file_obj.file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
            await update.message.reply_text(f"❌ File too large. Max: {MAX_FILE_SIZE_MB} MB")
            return

        temp_path = None
        status_msg = None

        try:
            status_msg = await update.message.reply_text("📥 Downloading file...")

            file = await context.bot.get_file(file_obj.file_id)
            temp_path = TEMP_DIR / f"{user_id}_{int(datetime.now().timestamp())}_{original_filename}"
            await file.download_to_drive(temp_path)

            actual_size = temp_path.stat().st_size
            file_hash = self._calculate_file_hash(temp_path)

            await self._safe_edit(status_msg, f"📥 Downloaded: {actual_size/1024/1024:.1f} MB\n🔍 Extracting metadata...")

            self.logger.log_security_event(
                user_id=user_id, action="ANALYSIS_START",
                file_hash=file_hash, additional_data={"filename": original_filename}
            )

            try:
                result = await asyncio.wait_for(
                    asyncio.to_thread(
                        self.extractor.extract_metadata,
                        str(temp_path),
                        original_filename,
                        ENABLE_GPS_LOOKUP
                    ),
                    timeout=EXTRACTION_TIMEOUT
                )
            except asyncio.TimeoutError:
                self.stats["total_analyses"] += 1
                self.stats["failed_analyses"] += 1
                await self._safe_edit(status_msg, f"❌ Timed out after {EXTRACTION_TIMEOUT}s")
                return

            await self._safe_edit(status_msg, "✅ Extraction complete! Formatting report...")

            self.stats["total_analyses"] += 1
            self.stats["successful_analyses"] += 1
            self.stats["total_users"].add(user_id)

            context.user_data["last_file_path"] = str(temp_path)
            context.user_data["last_result"] = result

            await self._safe_delete(status_msg)
            await self._send_report(update, result)

            self.logger.log_security_event(user_id=user_id, action="ANALYSIS_SUCCESS", file_hash=file_hash)

        except ExtractionError as e:
            self.stats["total_analyses"] += 1
            self.stats["failed_analyses"] += 1
            if status_msg:
                await self._safe_delete(status_msg)
            await update.message.reply_text(f"❌ Analysis Failed: {safe_str(e)}")

        except Exception as e:
            self.stats["total_analyses"] += 1
            self.stats["failed_analyses"] += 1
            if status_msg:
                await self._safe_delete(status_msg)
            self.logger.log_error(str(e), user_id=user_id)
            await update.message.reply_text("❌ An error occurred.")

    async def handle_document(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not self._check_auth(update.effective_user.id):
            return
        doc = update.message.document
        if doc.mime_type and doc.mime_type.startswith("image/"):
            await self.handle_image(update, context)
        else:
            await update.message.reply_text(
                f"❌ Unsupported type. Send image files only.",
                parse_mode="HTML"
            )

    async def handle_export_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        query = update.callback_query
        if not self._check_auth(query.from_user.id):
            await query.answer("Access Denied", show_alert=True)
            return
        await query.answer()
        if query.data == "export_json":
            result = context.user_data.get("last_result")
            if result:
                await self._export_json(query, result)
            else:
                await self._safe_edit(query.message, "❌ No data to export.")

    # =============================================
    # REPORT
    # =============================================

    async def _send_report(self, update: Update, result: ExtractionResult) -> None:
        """Send formatted report."""
        report = self._format_report(result)

        for chunk in self._split_message(report, 3900):
            await update.message.reply_text(chunk, parse_mode="HTML", disable_web_page_preview=True)

        keyboard = [[InlineKeyboardButton("📥 Export JSON", callback_data="export_json")]]
        await update.message.reply_text(
            "📤 Download full report:", reply_markup=InlineKeyboardMarkup(keyboard)
        )

        if result.gps_data and result.gps_data.latitude and result.gps_data.longitude:
            try:
                lat = float(result.gps_data.latitude)
                lon = float(result.gps_data.longitude)
                gm = f"https://maps.google.com/?q={lat},{lon}"
                osm = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=16"
                await update.message.reply_text(
                    f"🗺️ <b>MAPS</b>\n<a href='{gm}'>📍 Google Maps</a>\n<a href='{osm}'>📍 OpenStreetMap</a>",
                    parse_mode="HTML", disable_web_page_preview=False
                )
            except Exception:
                pass

    def _format_report(self, result: ExtractionResult) -> str:
        """Format extraction result - all values wrapped in safe_str()."""
        lines = [
            "🔍 <b>FORENSIC IMAGE ANALYSIS REPORT</b>",
            f"<code>━━━━━━━━━━━━━━━━━━━━━━</code>",
            f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            ""
        ]

        # GPS
        gps = result.gps_data
        if gps and gps.latitude is not None and gps.longitude is not None:
            try:
                lat_val = float(gps.latitude)
                lon_val = float(gps.longitude)
                lat_dir = "N" if lat_val >= 0 else "S"
                lon_dir = "E" if lon_val >= 0 else "W"
                lines.extend([
                    "📍 <b>GPS LOCATION</b>",
                    f"<code>━━━━━━━━━━━━━━━━━━━━━━</code>",
                    f"• <b>Lat:</b> {abs(lat_val):.6f}°{lat_dir}",
                    f"• <b>Lon:</b> {abs(lon_val):.6f}°{lon_dir}",
                ])
            except Exception:
                lines.extend([
                    "📍 <b>GPS LOCATION</b>",
                    f"<code>━━━━━━━━━━━━━━━━━━━━━━</code>",
                    f"• <b>Lat:</b> {safe_str(gps.latitude)}",
                    f"• <b>Lon:</b> {safe_str(gps.longitude)}",
                ])
            
            try:
                if gps.altitude is not None:
                    lines.append(f"• <b>Alt:</b> {float(gps.altitude):.1f}m")
            except Exception:
                if gps.altitude is not None:
                    lines.append(f"• <b>Alt:</b> {safe_str(gps.altitude)}m")
            
            if gps.timestamp:
                lines.append(f"• <b>Time:</b> {safe_str(gps.timestamp)}")
            if gps.satellite_count:
                lines.append(f"• <b>Satellites:</b> {safe_str(gps.satellite_count)}")
            if gps.address:
                lines.append(f"• <b>Address:</b> {safe_str(gps.address)}")
            lines.append("")

        # Device/Camera
        ed = result.exif_data
        if ed:
            if ed.camera_make or ed.camera_model:
                lines.extend([
                    "📱 <b>DEVICE / CAMERA</b>",
                    f"<code>━━━━━━━━━━━━━━━━━━━━━━</code>",
                ])
                if ed.camera_make:
                    lines.append(f"• <b>Make:</b> {safe_str(ed.camera_make)}")
                if ed.camera_model:
                    lines.append(f"• <b>Model:</b> {safe_str(ed.camera_model)}")
                if ed.camera_serial:
                    lines.append(f"• <b>Serial:</b> <code>{safe_str(ed.camera_serial)}</code>")
                if ed.lens_make:
                    lines.append(f"• <b>Lens Make:</b> {safe_str(ed.lens_make)}")
                if ed.lens_model:
                    lines.append(f"• <b>Lens:</b> {safe_str(ed.lens_model)}")
                if ed.software:
                    lines.append(f"• <b>Software:</b> {safe_str(ed.software)}")
                lines.append("")

            if any([ed.datetime_original, ed.exposure_time, ed.f_number, ed.iso is not None]):
                lines.extend([
                    "⚙️ <b>CAPTURE SETTINGS</b>",
                    f"<code>━━━━━━━━━━━━━━━━━━━━━━</code>",
                ])
                if ed.datetime_original:
                    lines.append(f"• <b>Date/Time:</b> {safe_str(ed.datetime_original)}")
                if ed.exposure_time:
                    lines.append(f"• <b>Exposure:</b> {safe_str(ed.exposure_time)}s")
                if ed.f_number:
                    lines.append(f"• <b>Aperture:</b> f/{safe_str(ed.f_number)}")
                if ed.iso is not None:
                    lines.append(f"• <b>ISO:</b> {safe_str(ed.iso)}")
                if ed.focal_length:
                    lines.append(f"• <b>Focal:</b> {safe_str(ed.focal_length)}mm")
                if ed.flash:
                    lines.append(f"• <b>Flash:</b> {safe_str(ed.flash)}")
                if ed.color_space:
                    lines.append(f"• <b>Color Space:</b> {safe_str(ed.color_space)}")
                lines.append("")

        # Image properties
        ip = result.image_properties
        if ip:
            lines.extend([
                "🖼️ <b>IMAGE PROPERTIES</b>",
                f"<code>━━━━━━━━━━━━━━━━━━━━━━</code>",
                f"• <b>Size:</b> {ip.width}×{ip.height}px | {ip.color_mode}",
            ])
            if ip.dpi:
                try:
                    lines.append(f"• <b>DPI:</b> {int(ip.dpi[0])}×{int(ip.dpi[1])}")
                except Exception:
                    lines.append(f"• <b>DPI:</b> {safe_str(ip.dpi)}")
            lines.append("")

        # File info
        fi = result.file_info
        if fi:
            lines.extend([
                "📁 <b>FILE INFO</b>",
                f"<code>━━━━━━━━━━━━━━━━━━━━━━</code>",
                f"• <b>Name:</b> <code>{safe_str(fi.filename)}</code>",
                f"• <b>Size:</b> {fi.size_mb:.2f} MB | {fi.format}",
            ])
            if fi.sha256:
                lines.append(f"• <b>SHA-256:</b> <code>{fi.sha256}</code>")
            if fi.md5:
                lines.append(f"• <b>MD5:</b> <code>{fi.md5}</code>")
            lines.append("")

        # Anomalies
        if result.anomalies:
            lines.extend([
                "⚠️ <b>ANOMALIES</b>",
                f"<code>━━━━━━━━━━━━━━━━━━━━━━</code>",
            ])
            for a in result.anomalies:
                lines.append(f"• {safe_str(a)}")
            lines.append("")

        lines.append(f"<code>━━━━━━━━━━━━━━━━━━━━━━</code>")
        lines.append("✅ <b>Analysis Complete</b>")
        return "\n".join(lines)

    @staticmethod
    def _split_message(text: str, max_len: int) -> List[str]:
        chunks, current = [], ""
        for line in text.split("\n"):
            if len(current) + len(line) + 1 > max_len:
                chunks.append(current.strip())
                current = line + "\n"
            else:
                current += line + "\n"
        if current.strip():
            chunks.append(current.strip())
        return chunks

    # =============================================
    # EXPORT
    # =============================================

    async def _export_json(self, query, result: ExtractionResult) -> None:
        try:
            data = {
                "timestamp": datetime.now().isoformat(),
                "file_info": asdict(result.file_info) if result.file_info else None,
                "exif_data": asdict(result.exif_data) if result.exif_data else None,
                "gps_data": asdict(result.gps_data) if result.gps_data else None,
                "image_properties": asdict(result.image_properties) if result.image_properties else None,
                "device_info": asdict(result.device_info) if result.device_info else None,
                "hidden_data": result.hidden_data or {},
                "anomalies": result.anomalies or [],
                "raw_exif": result.raw_exif or {},
            }
            fname = f"forensic_report_{int(datetime.now().timestamp())}.json"
            fpath = TEMP_DIR / fname
            with open(fpath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=safe_str, ensure_ascii=False)
            with open(fpath, "rb") as f:
                await query.message.reply_document(document=f, filename=fname, caption="📥 Forensic Report")
            fpath.unlink(missing_ok=True)
            await self._safe_edit(query.message, "✅ Exported!")
        except Exception as e:
            await self._safe_edit(query.message, f"❌ Export failed: {safe_str(e)}")

    # =============================================
    # UTILS
    # =============================================

    @staticmethod
    def _calculate_file_hash(file_path: Path, algo: str = "sha256") -> str:
        h = hashlib.new(algo)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    async def error_handler(self, update: Optional[Update], context: ContextTypes.DEFAULT_TYPE) -> None:
        err = context.error
        if err:
            err_str = str(err)
            if "Message to delete not found" in err_str:
                return
            if "Message is not modified" in err_str:
                return
            if "unsupported format string" in err_str:
                return
        self.logger.log_error(str(err) if err else "Unknown error")
        if err and hasattr(err, '__traceback__') and err.__traceback__:
            tb = "".join(traceback.format_tb(err.__traceback__))
            logging.error(f"Traceback:\n{tb}")


async def main() -> None:
    if not BOT_TOKEN:
        raise ValueError("❌ BOT_TOKEN not set in .env")
    if not AUTHORIZED_USERS:
        print("⚠️  No authorized users set. All users allowed.")

    setup_logging(LOG_LEVEL)
    logging.info("Starting Forensic Bot...")

    bot = ForensicBot(BOT_TOKEN)
    await bot.initialize()

    try:
        await bot.start()
        logging.info("✅ Bot running. Ctrl+C to stop.")
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        print("\n🛑 Shutting down...")
    finally:
        await bot.stop()


if __name__ == "__main__":
    asyncio.run(main())
