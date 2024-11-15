#Example of utilization of AWS CloudWatch with AdvancedLogger, make sure your AWS IAM credentials have permissions for the
#following actions: logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, logs:DescribeLogStreams

import logging
import boto3
from advanced_logger_module import AdvancedLogger, CloudWatchHandler  # Assuming the module is named `advanced_logger_module`

# Function to configure and initialize the AdvancedLogger with AWS CloudWatch
def setup_logger_with_cloudwatch():
    # Instantiate the AdvancedLogger
    logger = AdvancedLogger(
        name="MyAppLogger",
        log_level=logging.INFO,
        use_colors=True  # Optional: Use color-coded logs for console output
    )

    # AWS CloudWatch configuration
    log_group = "MyAppLogGroup"  # Replace with your CloudWatch Log Group name
    log_stream = "MyAppLogStream"  # Replace with your CloudWatch Log Stream name
    region_name = "us-east-1"  # AWS region, e.g., 'us-east-1'

    try:
        # Initialize and add the CloudWatchHandler
        cloudwatch_handler = CloudWatchHandler(
            log_group=log_group,
            log_stream=log_stream,
            region_name=region_name
        )
        cloudwatch_handler.setLevel(logging.INFO)
        logger.logger.addHandler(cloudwatch_handler)
        print("Successfully set up CloudWatch logging.")
    except Exception as e:
        print("Failed to set up CloudWatch logging:", e)

    return logger

# Example usage of the logger
logger = setup_logger_with_cloudwatch()

# Sending various logs
logger.log_info("Info: Application has started successfully.")
logger.log_warning("Warning: Low disk space detected.")
logger.log_error("Error: Unable to connect to the database.")
logger.log_critical("Critical: System is out of memory!")
