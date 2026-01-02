import sys
import re
import socket
from io import StringIO

from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QVBoxLayout, QHBoxLayout,
    QPushButton, QCheckBox, QLineEdit, QGroupBox,
    QRadioButton, QTextEdit, QMessageBox
)
from PySide6.QtCore import QThread, Signal, Qt

import analysis_m
import db_record_m

class AnalysisThread(QThread):
    log_signal = Signal(str)

    def __init__(self, target, selected_tools, pdf_report, html_report, db_on):
        super().__init__()
        self.target = target
        self.selected_tools = selected_tools
        self.pdf_report = pdf_report
        self.html_report = html_report
        self.db_on = db_on
        self.ANSI_ESCAPE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

    def strip_ansi(self, text: str) -> str:
        return self.ANSI_ESCAPE.sub('', text)

    def run(self):

        old_stdout = sys.stdout
        buffer = StringIO()
        sys.stdout = buffer
        try:
            analysis_m.analysis(self.target, self.selected_tools, self.pdf_report, self.html_report)
        finally:
            sys.stdout = old_stdout

        for line in buffer.getvalue().splitlines():
            clean = self.strip_ansi(line)
            if clean.strip():
                self.log_signal.emit(clean)

        if self.db_on:
            try:
                db_record_m.database_record(self.target)
                self.log_signal.emit(f"[+] Record added to the database")
            except Exception as e:
                self.log_signal.emit(f"[!] Database error: {e}")


class GeckoScanGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Gecko Scan")
        self.setMinimumWidth(520)
        self.init_ui()
        self.analysis_thread = None

    # connection check
    def ping(self, host, port=80, timeout=2):
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.close()
            return True
        except Exception:
            return False

    def check_whois(self, host='whois.verisign-grs.com', port=43, timeout=3):
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.close()
            return True
        except Exception:
            return False

    # UI
    def init_ui(self):
        main_layout = QVBoxLayout()

        # url input
        url_label = QLabel("Target URL:")
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        main_layout.addWidget(url_label)
        main_layout.addWidget(self.url_input)

        # tools
        tools_group = QGroupBox("Tools")
        tools_layout = QVBoxLayout()

        self.cb_virustotal = QCheckBox("VirusTotal")
        self.cb_whois = QCheckBox("Whois")
        self.cb_dnsdumpster = QCheckBox("DNSDumpster")
        self.cb_wheregoes = QCheckBox("WhereGoes")

        tools_layout.addWidget(self.cb_virustotal)
        tools_layout.addWidget(self.cb_whois)
        tools_layout.addWidget(self.cb_dnsdumpster)
        tools_layout.addWidget(self.cb_wheregoes)

        tools_group.setLayout(tools_layout)
        main_layout.addWidget(tools_group)

        #reports
        report_group = QGroupBox("Report")
        report_layout = QVBoxLayout()

        self.cb_pdf = QCheckBox("PDF")
        self.cb_pdf.setCheckState(Qt.CheckState.Checked)
        self.cb_html = QCheckBox("HTML")

        report_layout.addWidget(self.cb_pdf)
        report_layout.addWidget(self.cb_html)

        report_group.setLayout(report_layout)
        main_layout.addWidget(report_group)

        # database on/off
        db_group = QGroupBox("Database")
        db_layout = QHBoxLayout()

        self.rb_db_on = QRadioButton("ON")
        self.rb_db_off = QRadioButton("OFF")
        self.rb_db_on.setChecked(True)

        db_layout.addWidget(self.rb_db_on)
        db_layout.addWidget(self.rb_db_off)
        db_group.setLayout(db_layout)
        main_layout.addWidget(db_group)

        # run button
        self.run_button = QPushButton("Run Analysis")
        self.run_button.clicked.connect(self.start_analysis)
        main_layout.addWidget(self.run_button)

        # log
        log_group = QGroupBox("Log")
        log_layout = QVBoxLayout()

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setAcceptRichText(True)

        log_layout.addWidget(self.log_output)
        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group)

        self.setLayout(main_layout)

    # logging
    def log(self, message: str):
        if message.startswith("[+]"):
            color = "#2ecc71"   # green
        elif message.startswith("[!]"):
            color = "#e74c3c"   # red
        elif message.startswith("[~]"):
            color = "#f39c12"   # orange
        else:
            color = "#ecf0f1"   # default
        self.log_output.append(f'<span style="color:{color}">{message}</span>')

    def start_analysis(self):
        target = self.url_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "URL not selected!")
            return

        checkboxes_tools = [
            self.cb_virustotal,
            self.cb_whois,
            self.cb_dnsdumpster,
            self.cb_wheregoes
        ]
        if not any(cb.isChecked() for cb in checkboxes_tools):
            QMessageBox.warning(self, "Error", "You must choose at least one tool!")
            return

        self.log_output.clear()
        self.log("[+] Testing selected tools availability")

        # check availability
        selected_tools = []

        tool_tests = [
            (self.cb_virustotal, lambda: self.ping("virustotal.com"), "VirusTotal"),
            (self.cb_whois, self.check_whois, "Whois"),
            (self.cb_dnsdumpster, lambda: self.ping("dnsdumpster.com"), "DNSDumpster"),
            (self.cb_wheregoes, lambda: self.ping("wheregoes.com"), "WhereGoes"),
        ]

        for cb, test_func, name in tool_tests:
            if cb.isChecked():
                if test_func():
                    selected_tools.append(True)
                    self.log(f"[+] {name} OK")
                else:
                    selected_tools.append(False)
                    cb.setChecked(False)
                    self.log(f"[~] {name} not reachable – skipped")
            else:
                selected_tools.append(False)

        if not any(selected_tools):
            QMessageBox.warning(self, "Error", "Selected tools are not available.")
            return

        checkboxes_report = [
            self.cb_pdf,
            self.cb_html
        ]

        if not any(cb.isChecked() for cb in checkboxes_report):
            QMessageBox.warning(self, "Error", "You must choose at least one report type!")
            return
        
        pdf_wanted = self.cb_pdf.isChecked()
        html_wanted = self.cb_html.isChecked()

        db_on = self.rb_db_on.isChecked()

        # disable button to prevent double start
        self.run_button.setEnabled(False)

        # start thread
        self.analysis_thread = AnalysisThread(target, selected_tools, pdf_wanted, html_wanted, db_on)
        self.analysis_thread.log_signal.connect(self.log)
        self.analysis_thread.finished.connect(lambda: self.run_button.setEnabled(True))
        self.analysis_thread.start()


# main
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = GeckoScanGUI()
    window.show()
    sys.exit(app.exec())