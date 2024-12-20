![Screenshot 2024-11-20 222347](https://github.com/user-attachments/assets/21595c85-d9de-4868-a1f0-874555d0f183)

The application serves as a versatile tool for analyzing logs generated by the AdvancedLogger library or similar sources. It provides intuitive navigation, detailed viewing, and advanced filtering capabilities, making it ideal for developers and system administrators to manage and debug log files effectively.


Core Features
Log File Support
  -Supports both JSON logs and plain text logs. Both options of the library.
  -Automatically detects the log format and parses it accordingly.
   
Log Display
  -Logs are displayed in a scrollable, tabular format.
  -Columns are dynamically adjusted based on the log type:
  -JSON Logs: Timestamp, Level, Name, Message, Filename, Line Number.
  -Plain Text Logs: Timestamp, Filename, Level, Description.

Search and Filter
  -Allows filtering logs by specific fields (e.g., Level, Filename, Timestamp).
  -A dropdown menu provides filtering options or resets to "Show All" to display all logs.
  -Search bar dynamically filters logs based on user input.

Export Filtered Logs
  -Users can export filtered logs to a .log file.

Log Details Viewer
  -Clicking on a log entry opens a new window displaying its full details.
  -The viewer adapts its layout to the log type.

Log Statistics
  -Displays the total number of logs loaded and a breakdown of log levels (e.g., DEBUG, INFO, ERROR, etc.).

Dynamic UI Enhancements
  -Intuitive and visually appealing UI using the ttkbootstrap framework.


Near Future: I plan to add CLI support to this application which will allow AdvancedLogger to feed the logs in real time if user desired.

  
