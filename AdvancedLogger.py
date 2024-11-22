import logging
import logging.config
import logging.handlers
import json
import sys
import os
import gzip
import uuid
import re
import boto3 
from datetime import datetime
from typing import List, Optional, Dict
from concurrent.futures import ThreadPoolExecutor
import requests  


class LogColors:
    RESET = "\033[0m"
    DEBUG = "\033[94m"  # Blue
    INFO = "\033[92m"   # Green
    WARNING = "\033[93m"  # Yellow
    ERROR = "\033[91m"   # Red
    CRITICAL = "\033[95m"  # Magenta

class AdvancedLogger:
    def __init__(self, name: str, log_file: Optional[str] = None, log_level: int = logging.DEBUG,
                 use_custom_timestamp: bool = False, custom_time_format: Optional[str] = None,
                 use_colors: bool = False, use_trace_id: bool = False, use_json_format: bool = False,
                 context: Optional[Dict[str, str]] = None, enable_masking: bool = False,
                 audit_trail: Optional[str] = None, async_logging: bool = True):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(log_level)
        self.use_custom_timestamp = use_custom_timestamp
        self.custom_time_format = custom_time_format or "%d/%m/%y %H.%M.%S"
        self.use_colors = use_colors
        self.use_trace_id = use_trace_id
        self.use_json_format = use_json_format
        self.context = context or {}
        self.enable_masking = enable_masking
        self.audit_trail_file = audit_trail
        self.async_logging = async_logging
        self.executor = ThreadPoolExecutor(max_workers=2) if async_logging else None
        self.trace_id = str(uuid.uuid4()) if use_trace_id else None

        # Set up formatter
        self.formatter = self._get_formatter()

        # Set up handlers
        self.add_console_handler()
        if log_file:
            self.add_compressed_rotating_file_handler(log_file)
        if self.audit_trail_file:
            self._log_audit_trail("Logger initialized")

    def _get_formatter(self):
        """ Create a log formatter based on user preferences. """
        if self.use_json_format:
            return JSONFormatter()
        elif self.use_custom_timestamp:
            return logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt=self.custom_time_format
            )
        else:
            return logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    def _mask_sensitive_data(self, message: str) -> str:
        """ Mask sensitive data in log messages if enabled. """
        if not self.enable_masking:
            return message
        # Patterns for sensitive data
        patterns = [
            (r'\b\d{16}\b', '**** **** **** ****'),  # Mask credit card numbers
            (r'\b\d{3}-\d{2}-\d{4}\b', '***-**-****'),  # Mask SSNs
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '***@***.***')  # Mask emails
        ]
        for pattern, replacement in patterns:
            message = re.sub(pattern, replacement, message)
        return message

    def _log_audit_trail(self, message: str):
        """ Log audit trail entries to a separate file. """
        if self.audit_trail_file:
            with open(self.audit_trail_file, 'a') as f:
                f.write(f"{datetime.now().isoformat()} - {message}\n")

    def add_console_handler(self, log_level: int = logging.INFO):
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(self.formatter)
        self.logger.addHandler(console_handler)

    def add_compressed_rotating_file_handler(self, log_file: str, max_bytes: int = 1024 * 1024 * 5, backup_count: int = 5, log_level: int = logging.DEBUG):
        """ Add a compressed rotating file handler to the logger. """
        try:
            class CompressedRotatingFileHandler(logging.handlers.RotatingFileHandler):
                def doRollover(self):
                    super().doRollover()
                    if self.backupCount > 0:
                        old_log = f"{self.baseFilename}.1"
                        if os.path.exists(old_log):
                            with open(old_log, 'rb') as f_in, gzip.open(f"{old_log}.gz", 'wb') as f_out:
                                f_out.writelines(f_in)
                            os.remove(old_log)

            rotating_handler = CompressedRotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
            rotating_handler.setLevel(log_level)
            rotating_handler.setFormatter(self.formatter)
            self.logger.addHandler(rotating_handler)
        except Exception as e:
            self.logger.error("Failed to initialize file handler: " + str(e))

    def log_with_context(self, message: str, level: int = logging.INFO):
        """ Log a message with additional context and an optional trace ID. """
        context_str = " ".join(f"{key}={value}" for key, value in self.context.items())
        trace_str = f"[TraceID: {self.trace_id}] " if self.trace_id else ""
        full_message = f"{trace_str}{context_str} {self._mask_sensitive_data(message)}"
        if self.async_logging and self.executor:
            self.executor.submit(self.logger.log, level, full_message)
        else:
            self.logger.log(level, full_message)

    # Additional methods for logging at various levels
    def log_debug(self, message: str):
        self.log_with_context(message, logging.DEBUG)

    def log_info(self, message: str):
        self.log_with_context(message, logging.INFO)

    def log_warning(self, message: str):
        self.log_with_context(message, logging.WARNING)

    def log_error(self, message: str):
        self.log_with_context(message, logging.ERROR)

    def log_critical(self, message: str):
        self.log_with_context(message, logging.CRITICAL)


class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
            "filename": record.filename,
            "line_number": record.lineno
        }
        return json.dumps(log_entry)


class SplunkHandler(logging.Handler):
    def __init__(self, splunk_url: str, token: str):
        super().__init__()
        self.splunk_url = splunk_url
        self.token = token

    def emit(self, record):
        log_entry = self.format(record)
        headers = {
            "Authorization": f"Splunk {self.token}"
        }
        try:
            response = requests.post(self.splunk_url, headers=headers, data=log_entry)
            if response.status_code != 200:
                raise Exception(f"Failed to send log to Splunk: {response.status_code} {response.text}")
        except Exception as e:
            print("Error sending log to Splunk:", e)

class CloudWatchHandler(logging.Handler):
    def __init__(self, log_group: str, log_stream: str, region_name: str):
        super().__init__()
        self.client = boto3.client('logs', region_name=region_name)
        self.log_group = log_group
        self.log_stream = log_stream
        self.sequence_token = None
        self._initialize_stream()

    def _initialize_stream(self):
        try:
            response = self.client.describe_log_streams(
                logGroupName=self.log_group,
                logStreamNamePrefix=self.log_stream
            )
            if "logStreams" in response and len(response["logStreams"]) > 0:
                self.sequence_token = response["logStreams"][0].get("uploadSequenceToken")
            else:
                self.client.create_log_stream(logGroupName=self.log_group, logStreamName=self.log_stream)
        except Exception as e:
            print("Error initializing CloudWatch log stream:", e)

    def emit(self, record):
        log_entry = self.format(record)
        try:
            response = self.client.put_log_events(
                logGroupName=self.log_group,
                logStreamName=self.log_stream,
                logEvents=[
                    {
                        "timestamp": int(datetime.utcnow().timestamp() * 1000),
                        "message": log_entry
                    }
                ],
                sequenceToken=self.sequence_token
            )
            self.sequence_token = response.get("nextSequenceToken")
        except Exception as e:
            print("Error sending log to CloudWatch:", e)

