import logging
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
from logging.handlers import RotatingFileHandler

# Log directory
LOG_DIR = Path.home() / ".forensic_bot" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Log file paths
MAIN_LOG_FILE = LOG_DIR / "forensic_bot.log"
SECURITY_LOG_FILE = LOG_DIR / "security_audit.log"
ERROR_LOG_FILE = LOG_DIR / "errors.log"
CHAIN_OF_CUSTODY_LOG = LOG_DIR / "chain_of_custody.log"


class JSONFormatter(logging.Formatter):
    """Format logs as JSON for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)


class ForensicsLogger:
    """
    Specialized logger for forensic analysis with chain of custody support.
    """

    def __init__(self, name: str):
        """
        Initialize forensics logger.

        Args:
            name: Logger name
        """
        self.name = name
        self.logger = logging.getLogger(name)
        self.audit_logger = logging.getLogger(f"{name}.audit")
        self.chain_logger = logging.getLogger(f"{name}.chain_of_custody")

    def log_info(self, message: str, **kwargs) -> None:
        """Log informational message."""
        self.logger.info(message)

    def log_debug(self, message: str, **kwargs) -> None:
        """Log debug message."""
        self.logger.debug(message)

    def log_warning(self, message: str, **kwargs) -> None:
        """Log warning message."""
        self.logger.warning(message)

    def log_error(
        self,
        message: str,
        user_id: Optional[int] = None,
        error_type: Optional[str] = None,
        **kwargs,
    ) -> None:
        """
        Log error message with context.

        Args:
            message: Error message
            user_id: Telegram user ID (if applicable)
            error_type: Type of error
            **kwargs: Additional context
        """
        error_context = {
            "timestamp": datetime.utcnow().isoformat(),
            "message": message,
            "error_type": error_type,
            "user_id": user_id,
            **kwargs,
        }

        # Also log to dedicated error logger
        error_logger = logging.getLogger("ForensicBot.errors")
        error_logger.error(json.dumps(error_context))
        
        # Log to main logger as well
        self.logger.error(json.dumps(error_context))

    def log_security_event(
        self,
        user_id: int,
        action: str,
        status: str = "SUCCESS",
        file_hash: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log security-relevant event for audit trail.

        Args:
            user_id: Telegram user ID
            action: Action performed
            status: Status of action (SUCCESS, DENIED, FAILED, etc.)
            file_hash: File hash if applicable
            additional_data: Additional context
        """
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "action": action,
            "status": status,
            "file_hash": file_hash,
            "additional_data": additional_data or {},
        }

        self.audit_logger.warning(json.dumps(audit_entry))

    def log_chain_of_custody(
        self,
        user_id: int,
        file_hash: str,
        action: str,
        file_path: Optional[str] = None,
        metadata_extracted: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log chain of custody entry for forensic evidence.

        Args:
            user_id: Analyst ID (Telegram user ID)
            file_hash: SHA-256 hash of evidence file
            action: Action taken (RECEIVED, ANALYZED, EXPORTED, etc.)
            file_path: Path to evidence file
            metadata_extracted: Metadata extracted from file
        """
        custody_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "analyst_id": user_id,
            "file_hash": file_hash,
            "action": action,
            "file_path": file_path,
            "metadata_count": len(metadata_extracted) if metadata_extracted else 0,
            "evidence_status": "PRESERVED",
        }

        self.chain_logger.warning(json.dumps(custody_entry))

    def log_file_analysis(
        self,
        file_hash: str,
        file_name: str,
        file_size: int,
        format_type: str,
        anomalies: Optional[list] = None,
    ) -> None:
        """
        Log file analysis details.

        Args:
            file_hash: SHA-256 hash
            file_name: Original filename
            file_size: File size in bytes
            format_type: File format
            anomalies: Detected anomalies
        """
        analysis_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "file_hash": file_hash,
            "file_name": file_name,
            "file_size": file_size,
            "format": format_type,
            "anomalies": anomalies or [],
            "analysis_status": "COMPLETED",
        }

        self.logger.info(json.dumps(analysis_entry))


def setup_logging(level: str = "INFO") -> None:
    """
    Configure logging for the forensic bot.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    # Suppress noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("telegram").setLevel(logging.WARNING)

    # Main application logger
    app_logger = logging.getLogger("ForensicBot")
    app_logger.setLevel(log_level)

    # Main log handler (rotating)
    main_handler = RotatingFileHandler(
        MAIN_LOG_FILE,
        maxBytes=50 * 1024 * 1024,  # 50 MB
        backupCount=10,
        encoding="utf-8",
    )
    main_handler.setFormatter(JSONFormatter())
    app_logger.addHandler(main_handler)

    # Console handler for development
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    console_handler.setFormatter(console_formatter)
    app_logger.addHandler(console_handler)

    # Security audit logger
    security_logger = logging.getLogger("ForensicBot.audit")
    security_logger.setLevel(logging.WARNING)  # Always log audit events
    security_handler = RotatingFileHandler(
        SECURITY_LOG_FILE,
        maxBytes=50 * 1024 * 1024,
        backupCount=20,
        encoding="utf-8",
    )
    security_handler.setFormatter(JSONFormatter())
    security_logger.addHandler(security_handler)
    security_logger.propagate = False

    # Chain of custody logger
    custody_logger = logging.getLogger("ForensicBot.chain_of_custody")
    custody_logger.setLevel(logging.WARNING)  # Always log
    custody_handler = RotatingFileHandler(
        CHAIN_OF_CUSTODY_LOG,
        maxBytes=100 * 1024 * 1024,  # 100 MB for longer retention
        backupCount=30,
        encoding="utf-8",
    )
    custody_handler.setFormatter(JSONFormatter())
    custody_logger.addHandler(custody_handler)
    custody_logger.propagate = False

    # Error logger
    error_logger = logging.getLogger("ForensicBot.errors")
    error_logger.setLevel(logging.ERROR)
    error_handler = RotatingFileHandler(
        ERROR_LOG_FILE,
        maxBytes=50 * 1024 * 1024,
        backupCount=15,
        encoding="utf-8",
    )
    error_handler.setFormatter(JSONFormatter())
    error_logger.addHandler(error_handler)
    error_logger.propagate = False

    logging.info(f"Logging configured at level: {level}")
    logging.info(f"Log directory: {LOG_DIR}")


def get_logger(name: str) -> ForensicsLogger:
    """
    Get a forensics logger instance.

    Args:
        name: Logger name

    Returns:
        ForensicsLogger instance
    """
    return ForensicsLogger(name)


def generate_audit_report(start_date: Optional[datetime] = None) -> str:
    """
    Generate audit report from security logs.

    Args:
        start_date: Start date for report (default: last 24 hours)

    Returns:
        Formatted audit report
    """
    if not start_date:
        from datetime import timedelta
        start_date = datetime.utcnow() - timedelta(hours=24)

    report_lines = [
        f"Forensic Bot Audit Report",
        f"Generated: {datetime.utcnow().isoformat()}",
        f"Period: {start_date.isoformat()} to {datetime.utcnow().isoformat()}",
        "",
    ]

    # Parse audit log
    if SECURITY_LOG_FILE.exists():
        report_lines.append("Security Events:")
        try:
            with open(SECURITY_LOG_FILE, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        entry_time = datetime.fromisoformat(entry.get("timestamp", ""))
                        if entry_time >= start_date:
                            report_lines.append(
                                f"  [{entry['timestamp']}] "
                                f"User {entry.get('user_id')}: "
                                f"{entry.get('action')} - {entry.get('status')}"
                            )
                    except (json.JSONDecodeError, KeyError, ValueError):
                        pass
        except Exception:
            report_lines.append("  Error reading security log")

    report_lines.append("")

    # Parse chain of custody log
    if CHAIN_OF_CUSTODY_LOG.exists():
        report_lines.append("Chain of Custody:")
        try:
            with open(CHAIN_OF_CUSTODY_LOG, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        entry_time = datetime.fromisoformat(entry.get("timestamp", ""))
                        if entry_time >= start_date:
                            report_lines.append(
                                f"  [{entry['timestamp']}] "
                                f"Analyst {entry.get('analyst_id')}: "
                                f"{entry.get('action')} on {entry.get('file_hash', 'unknown')[:16]}..."
                            )
                    except (json.JSONDecodeError, KeyError, ValueError):
                        pass
        except Exception:
            report_lines.append("  Error reading custody log")

    return "\n".join(report_lines)#!/usr/bin/env python3
"""
Forensic Logging Configuration

Implements chain of custody logging, audit trails, and secure logging practices
for forensic image analysis.

Author: Forensic Analysis System
"""

import logging
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
from logging.handlers import RotatingFileHandler

# Log directory
LOG_DIR = Path.home() / ".forensic_bot" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Log file paths
MAIN_LOG_FILE = LOG_DIR / "forensic_bot.log"
SECURITY_LOG_FILE = LOG_DIR / "security_audit.log"
ERROR_LOG_FILE = LOG_DIR / "errors.log"
CHAIN_OF_CUSTODY_LOG = LOG_DIR / "chain_of_custody.log"


class JSONFormatter(logging.Formatter):
    """Format logs as JSON for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)


class ForensicsLogger:
    """
    Specialized logger for forensic analysis with chain of custody support.
    """

    def __init__(self, name: str):
        """
        Initialize forensics logger.

        Args:
            name: Logger name
        """
        self.name = name
        self.logger = logging.getLogger(name)
        self.audit_logger = logging.getLogger(f"{name}.audit")
        self.chain_logger = logging.getLogger(f"{name}.chain_of_custody")

    def log_info(self, message: str, **kwargs) -> None:
        """Log informational message."""
        self.logger.info(message)

    def log_debug(self, message: str, **kwargs) -> None:
        """Log debug message."""
        self.logger.debug(message)

    def log_warning(self, message: str, **kwargs) -> None:
        """Log warning message."""
        self.logger.warning(message)

    def log_error(
        self,
        message: str,
        user_id: Optional[int] = None,
        error_type: Optional[str] = None,
        **kwargs,
    ) -> None:
        """
        Log error message with context.

        Args:
            message: Error message
            user_id: Telegram user ID (if applicable)
            error_type: Type of error
            **kwargs: Additional context
        """
        error_context = {
            "timestamp": datetime.utcnow().isoformat(),
            "message": message,
            "error_type": error_type,
            "user_id": user_id,
            **kwargs,
        }

        # Also log to dedicated error logger
        error_logger = logging.getLogger("ForensicBot.errors")
        error_logger.error(json.dumps(error_context))
        
        # Log to main logger as well
        self.logger.error(json.dumps(error_context))

    def log_security_event(
        self,
        user_id: int,
        action: str,
        status: str = "SUCCESS",
        file_hash: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log security-relevant event for audit trail.

        Args:
            user_id: Telegram user ID
            action: Action performed
            status: Status of action (SUCCESS, DENIED, FAILED, etc.)
            file_hash: File hash if applicable
            additional_data: Additional context
        """
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "action": action,
            "status": status,
            "file_hash": file_hash,
            "additional_data": additional_data or {},
        }

        self.audit_logger.warning(json.dumps(audit_entry))

    def log_chain_of_custody(
        self,
        user_id: int,
        file_hash: str,
        action: str,
        file_path: Optional[str] = None,
        metadata_extracted: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log chain of custody entry for forensic evidence.

        Args:
            user_id: Analyst ID (Telegram user ID)
            file_hash: SHA-256 hash of evidence file
            action: Action taken (RECEIVED, ANALYZED, EXPORTED, etc.)
            file_path: Path to evidence file
            metadata_extracted: Metadata extracted from file
        """
        custody_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "analyst_id": user_id,
            "file_hash": file_hash,
            "action": action,
            "file_path": file_path,
            "metadata_count": len(metadata_extracted) if metadata_extracted else 0,
            "evidence_status": "PRESERVED",
        }

        self.chain_logger.warning(json.dumps(custody_entry))

    def log_file_analysis(
        self,
        file_hash: str,
        file_name: str,
        file_size: int,
        format_type: str,
        anomalies: Optional[list] = None,
    ) -> None:
        """
        Log file analysis details.

        Args:
            file_hash: SHA-256 hash
            file_name: Original filename
            file_size: File size in bytes
            format_type: File format
            anomalies: Detected anomalies
        """
        analysis_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "file_hash": file_hash,
            "file_name": file_name,
            "file_size": file_size,
            "format": format_type,
            "anomalies": anomalies or [],
            "analysis_status": "COMPLETED",
        }

        self.logger.info(json.dumps(analysis_entry))


def setup_logging(level: str = "INFO") -> None:
    """
    Configure logging for the forensic bot.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    # Suppress noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("telegram").setLevel(logging.WARNING)

    # Main application logger
    app_logger = logging.getLogger("ForensicBot")
    app_logger.setLevel(log_level)

    # Main log handler (rotating)
    main_handler = RotatingFileHandler(
        MAIN_LOG_FILE,
        maxBytes=50 * 1024 * 1024,  # 50 MB
        backupCount=10,
        encoding="utf-8",
    )
    main_handler.setFormatter(JSONFormatter())
    app_logger.addHandler(main_handler)

    # Console handler for development
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    console_handler.setFormatter(console_formatter)
    app_logger.addHandler(console_handler)

    # Security audit logger
    security_logger = logging.getLogger("ForensicBot.audit")
    security_logger.setLevel(logging.WARNING)  # Always log audit events
    security_handler = RotatingFileHandler(
        SECURITY_LOG_FILE,
        maxBytes=50 * 1024 * 1024,
        backupCount=20,
        encoding="utf-8",
    )
    security_handler.setFormatter(JSONFormatter())
    security_logger.addHandler(security_handler)
    security_logger.propagate = False

    # Chain of custody logger
    custody_logger = logging.getLogger("ForensicBot.chain_of_custody")
    custody_logger.setLevel(logging.WARNING)  # Always log
    custody_handler = RotatingFileHandler(
        CHAIN_OF_CUSTODY_LOG,
        maxBytes=100 * 1024 * 1024,  # 100 MB for longer retention
        backupCount=30,
        encoding="utf-8",
    )
    custody_handler.setFormatter(JSONFormatter())
    custody_logger.addHandler(custody_handler)
    custody_logger.propagate = False

    # Error logger
    error_logger = logging.getLogger("ForensicBot.errors")
    error_logger.setLevel(logging.ERROR)
    error_handler = RotatingFileHandler(
        ERROR_LOG_FILE,
        maxBytes=50 * 1024 * 1024,
        backupCount=15,
        encoding="utf-8",
    )
    error_handler.setFormatter(JSONFormatter())
    error_logger.addHandler(error_handler)
    error_logger.propagate = False

    logging.info(f"Logging configured at level: {level}")
    logging.info(f"Log directory: {LOG_DIR}")


def get_logger(name: str) -> ForensicsLogger:
    """
    Get a forensics logger instance.

    Args:
        name: Logger name

    Returns:
        ForensicsLogger instance
    """
    return ForensicsLogger(name)


def generate_audit_report(start_date: Optional[datetime] = None) -> str:
    """
    Generate audit report from security logs.

    Args:
        start_date: Start date for report (default: last 24 hours)

    Returns:
        Formatted audit report
    """
    if not start_date:
        from datetime import timedelta
        start_date = datetime.utcnow() - timedelta(hours=24)

    report_lines = [
        f"Forensic Bot Audit Report",
        f"Generated: {datetime.utcnow().isoformat()}",
        f"Period: {start_date.isoformat()} to {datetime.utcnow().isoformat()}",
        "",
    ]

    # Parse audit log
    if SECURITY_LOG_FILE.exists():
        report_lines.append("Security Events:")
        try:
            with open(SECURITY_LOG_FILE, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        entry_time = datetime.fromisoformat(entry.get("timestamp", ""))
                        if entry_time >= start_date:
                            report_lines.append(
                                f"  [{entry['timestamp']}] "
                                f"User {entry.get('user_id')}: "
                                f"{entry.get('action')} - {entry.get('status')}"
                            )
                    except (json.JSONDecodeError, KeyError, ValueError):
                        pass
        except Exception:
            report_lines.append("  Error reading security log")

    report_lines.append("")

    # Parse chain of custody log
    if CHAIN_OF_CUSTODY_LOG.exists():
        report_lines.append("Chain of Custody:")
        try:
            with open(CHAIN_OF_CUSTODY_LOG, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        entry_time = datetime.fromisoformat(entry.get("timestamp", ""))
                        if entry_time >= start_date:
                            report_lines.append(
                                f"  [{entry['timestamp']}] "
                                f"Analyst {entry.get('analyst_id')}: "
                                f"{entry.get('action')} on {entry.get('file_hash', 'unknown')[:16]}..."
                            )
                    except (json.JSONDecodeError, KeyError, ValueError):
                        pass
        except Exception:
            report_lines.append("  Error reading custody log")

    return "\n".join(report_lines)
