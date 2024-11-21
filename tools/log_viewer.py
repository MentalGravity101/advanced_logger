#Author: Dustan Gunn, 11/20/24, for use with the AdvancedLogger library .log files. It can run either .log export type, the plain text method or json method utilized by the library.

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import ttkbootstrap as tb
import pandas as pd
import json


class LogViewerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Log Viewer")
        self.root.geometry("1600x750")
        self.log_format = None
        self.style = tb.Style("darkly")

        self.top_frame = ttk.Frame(self.root)
        self.top_frame.pack(fill=tk.X, padx=10, pady=5)

        self.load_button = ttk.Button(self.top_frame, text="Load Log File", command=self.load_log)
        self.load_button.pack(side=tk.LEFT, padx=5)

        self.filter_var = tk.StringVar(value="Show All")
        self.filter_menu = ttk.Combobox(
            self.top_frame,
            textvariable=self.filter_var,
            state="readonly",
            values=["Show All", "timestamp", "level", "name", "filename", "line_number"]
        )
        self.filter_menu.pack(side=tk.LEFT, padx=5)
        self.filter_menu.bind("<<ComboboxSelected>>", self.update_filter)

        self.search_label = ttk.Label(self.top_frame, text="Search:")
        self.search_label.pack(side=tk.LEFT, padx=5)

        self.search_entry = ttk.Entry(self.top_frame, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=5)

        self.search_button = ttk.Button(self.top_frame, text="Search", command=self.search_logs)
        self.search_button.pack(side=tk.LEFT, padx=5)

        self.export_button = ttk.Button(self.top_frame, text="Export Filtered", command=self.export_filtered_logs)
        self.export_button.pack(side=tk.LEFT, padx=5)

        self.output_frame = ttk.Frame(self.root)
        self.output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.tree = ttk.Treeview(
            self.output_frame,
            columns=("timestamp", "level", "name", "filename", "line_number", "message"),
            show="headings"
        )
        self.tree.heading("timestamp", text="Timestamp")
        self.tree.heading("level", text="Level")
        self.tree.heading("name", text="Name")
        self.tree.heading("filename", text="Filename")
        self.tree.heading("line_number", text="Line Number")
        self.tree.heading("message", text="Message")
        self.tree.bind("<Double-1>", self.show_log_details)

        for col in self.tree["columns"]:
            self.tree.column(col, anchor=tk.CENTER)

        y_scroll = ttk.Scrollbar(self.output_frame, orient=tk.VERTICAL, command=self.tree.yview)
        x_scroll = ttk.Scrollbar(self.output_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscroll=y_scroll.set, xscroll=x_scroll.set)

        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        x_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(fill=tk.BOTH, expand=True)

        self.stats_label = ttk.Label(self.root, text="Log Stats: No file loaded", anchor="w")
        self.stats_label.pack(fill=tk.X, padx=10, pady=5)

        self.log_data = None

    def export_filtered_logs(self):
        if self.log_data is None or self.log_data.empty:
            messagebox.showwarning("Export Error", "There are no logs to export.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Save Filtered Logs",
            defaultextension=".log",
            filetypes=[("Log Files", "*.log"), ("All Files", "*.*")]
        )

        if not file_path:
            return

        try:
            with open(file_path, 'w') as log_file:
                for _, row in self.log_data.iterrows():
                    if 'line_number' in row:
                        log_line = f'{row["timestamp"]} - {row["filename"]} - {row["level"]} - {row["name"]} - {row["line_number"]} - {row["message"]}'
                    else:
                        log_line = f'{row["timestamp"]} - {row["filename"]} - {row["level"]} - {row["message"]}'
                    log_file.write(log_line + '\n')

            messagebox.showinfo("Export Successful", f"Filtered logs saved to {file_path}.")
        except Exception as e:
            messagebox.showerror("Export Error", f"An error occurred while saving logs: {e}")

    def show_log_details(self, event):
        selected_item = self.tree.selection()
        if not selected_item:
            return

        log_details = self.tree.item(selected_item[0], "values")

        detail_window = tk.Toplevel(self.root)
        detail_window.title("Log Details")
        detail_window.geometry("600x400")

        text_widget = tk.Text(detail_window, wrap=tk.WORD, font=("Helvetica", 10))
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        if self.log_format == "json":
            detail_text = (
                f"Timestamp: {log_details[0]}\n"
                f"Level: {log_details[1]}\n"
                f"Name: {log_details[2]}\n"
                f"Message: {log_details[3]}\n"
                f"Filename: {log_details[4]}\n"
                f"Line Number: {log_details[5]}"
            )
        elif self.log_format == "plain":
            detail_text = (
                f"Timestamp: {log_details[0]}\n"
                f"Filename: {log_details[2]}\n"
                f"Level: {log_details[1]}\n"
                f"Message: {log_details[5]}"
            )
        else:
            detail_text = "Log format not recognized."

        text_widget.insert(tk.END, detail_text)
        text_widget.config(state=tk.DISABLED)

    def load_log(self):
        file_path = filedialog.askopenfilename(
            title="Select a Log File",
            filetypes=[("Log Files", "*.log"), ("All Files", "*.*")]
        )
        if not file_path:
            return

        try:
            with open(file_path, "r") as file:
                content = file.read()

            if content.lstrip().startswith("{"):
                self.log_format = 'json'
                logs = []
                for line in content.splitlines():
                    try:
                        log = json.loads(line)
                        logs.append({
                            "timestamp": log.get("timestamp", "N/A"),
                            "level": log.get("level", "N/A"),
                            "name": log.get("name", "N/A"),
                            "filename": log.get("filename", "N/A"),
                            "line_number": log.get("line_number", "N/A"),
                            "message": log.get("message", "N/A")
                        })
                    except json.JSONDecodeError:
                        print(f"Invalid JSON line: {line}")
                self.log_data = pd.DataFrame(logs)

            else:
                self.log_format = 'plain'
                logs = []
                for line in content.splitlines():
                    parts = line.split(" - ")
                    if len(parts) >= 4:
                        timestamp = parts[0].strip()
                        name = parts[1].strip()
                        level = parts[2].strip()
                        description = " - ".join(parts[3:]).strip()
                        logs.append({
                            "timestamp": timestamp,
                            "level": level,
                            "name": name,
                            "filename": "N/A",
                            "line_number": "N/A",
                            "message": description
                        })
                    else:
                        print(f"Invalid plain text line: {line}")
                if logs:
                    self.log_data = pd.DataFrame(logs)
                else:
                    messagebox.showwarning("Invalid File",
                                           "The file does not match the expected plain text log format.")

            self.populate_table()
            self.update_stats()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load log file: {e}")

    def populate_table(self):
        if self.log_data is not None:
            for item in self.tree.get_children():
                self.tree.delete(item)

            for _, row in self.log_data.iterrows():
                self.tree.insert("", tk.END, values=row.tolist())

    def update_stats(self):
        if self.log_data is not None:
            total_logs = len(self.log_data)
            level_counts = self.log_data["level"].value_counts().to_dict()
            stats_text = f"Total Logs: {total_logs} | " + " | ".join(
                f"{level}: {count}" for level, count in level_counts.items())
            self.stats_label.config(text=stats_text)

    def update_filter(self, event=None):
        selected_filter = self.filter_var.get()
        if selected_filter == "Show All":
            self.search_entry.delete(0, tk.END)
            self.populate_table()

    def search_logs(self):
        query = self.search_entry.get().lower()
        selected_filter = self.filter_var.get()

        if not query or self.log_data is None:
            return

        if selected_filter == "Show All":
            filtered_data = self.log_data[
                self.log_data.apply(lambda row: row.astype(str).str.contains(query).any(), axis=1)
            ]
        else:
            filtered_data = self.log_data[
                self.log_data[selected_filter].astype(str).str.contains(query, case=False)
            ]

        self.log_data = filtered_data
        self.populate_table()


if __name__ == "__main__":
    root = tb.Window(themename="darkly")
    app = LogViewerApp(root)
    root.mainloop()

