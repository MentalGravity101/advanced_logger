# Initialize the logger with Splunk integration
logger = AdvancedLogger(
    name="MyAppLogger",
    log_level=logging.WARNING,  # Log level set to WARNING
    use_colors=False,  # Disable colors (Splunk will handle formatting)
    use_trace_id=True,  # Generate a trace ID for each log
    use_json_format=False,  # Logs will be in plain text format
    context={"user": "user456", "operation": "update"},  # Additional context
    enable_masking=True,  # Mask sensitive data
    async_logging=True  # Enable asynchronous logging
)

# Add Splunk handler to the logger
splunk_handler = SplunkHandler(
    splunk_url="https://splunk.example.com:8088/services/collector/event"
    token="your_splunk_token"
)
logger.logger.addHandler(splunk_handler)

# Example log message that will be sent to Splunk
logger.log_warning("Update operation completed with warnings.")
