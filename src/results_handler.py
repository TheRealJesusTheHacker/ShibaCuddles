"""
Results handler for exporting scan results in multiple formats.
"""

import csv
import json
import logging
import xml.dom.minidom as minidom
import xml.etree.ElementTree as ET
from dataclasses import asdict
from pathlib import Path
from typing import List


class ResultsHandler:
    """
    Handle saving and formatting scan results in multiple formats.
    """

    def __init__(self, logger: logging.Logger = None):
        """
        Initialize results handler.

        Args:
            logger: Logger instance
        """
        self.logger = logger or logging.getLogger(__name__)

    def save(
        self, results: List, filepath: str, format: str = "json", force: bool = False
    ) -> bool:
        """
        Save results to file in specified format.

        Args:
            results: List of scan results
            filepath: Output file path
            format: Output format (json, csv, xml, txt)

        Returns:
            True if successful, False otherwise
        """
        try:
            if not force and Path(filepath).exists():
                raise FileExistsError(
                    f"Refusing to overwrite existing file: {filepath} "
                    "(pass force=True or use --force to overwrite)"
                )
            # Auto-detect format from file extension if not specified
            if format == "json" and filepath.endswith(".csv"):
                format = "csv"
            elif format == "json" and filepath.endswith(".xml"):
                format = "xml"
            elif format == "json" and filepath.endswith(".txt"):
                format = "txt"

            # Save in requested format
            if format == "json":
                self._save_json(results, filepath)
            elif format == "csv":
                self._save_csv(results, filepath)
            elif format == "xml":
                self._save_xml(results, filepath)
            elif format == "txt":
                self._save_txt(results, filepath)
            else:
                raise ValueError(f"Unsupported format: {format}")

            self.logger.info(f"Results saved to {filepath}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")
            return False

    def _save_json(self, results: List, filepath: str) -> None:
        """Save results as JSON."""
        results_dict = []
        for result in results:
            if hasattr(result, "__dataclass_fields__"):
                results_dict.append(asdict(result))
            else:
                results_dict.append(result)

        with open(filepath, "w") as f:
            json.dump(results_dict, f, indent=2)

    def _save_csv(self, results: List, filepath: str) -> None:
        """Save results as CSV."""
        if not results:
            return

        rows = []
        for result in results:
            if hasattr(result, "__dataclass_fields__"):
                result_dict = asdict(result)
            else:
                result_dict = result

            flat_row = {
                "ip": result_dict.get("ip", ""),
                "alive": result_dict.get("alive", ""),
                "open_ports": ",".join(map(str, result_dict.get("open_ports", []))),
                "port_count": len(result_dict.get("open_ports", [])),
                "scan_time": result_dict.get("scan_time", ""),
            }
            rows.append(flat_row)

        if rows:
            with open(filepath, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)

    def _save_xml(self, results: List, filepath: str) -> None:
        """Save results as XML."""
        root = ET.Element("ShibaCuddles")
        root.set("version", "1.0")

        scan_results = ET.SubElement(root, "ScanResults")

        for result in results:
            if hasattr(result, "__dataclass_fields__"):
                result_dict = asdict(result)
            else:
                result_dict = result

            host_elem = ET.SubElement(scan_results, "Host")
            host_elem.set("ip", str(result_dict.get("ip", "")))
            host_elem.set("alive", str(result_dict.get("alive", "")))

            open_ports_elem = ET.SubElement(host_elem, "OpenPorts")
            for port in result_dict.get("open_ports", []):
                port_elem = ET.SubElement(open_ports_elem, "Port")
                port_elem.text = str(port)

            services = result_dict.get("services", {})
            if services:
                services_elem = ET.SubElement(host_elem, "Services")
                for port, service_info in services.items():
                    service_elem = ET.SubElement(services_elem, "Service")
                    service_elem.set("port", str(port))
                    service_elem.set("name", service_info.get("name", "Unknown"))
                    if service_info.get("version"):
                        service_elem.set("version", service_info["version"])

            if result_dict.get("scan_time"):
                time_elem = ET.SubElement(host_elem, "ScanTime")
                time_elem.text = str(result_dict["scan_time"])

        xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
        with open(filepath, "w") as f:
            f.write("\n".join(xml_str.split("\n")[1:]))

    def _save_txt(self, results: List, filepath: str) -> None:
        """Save results as human-readable text."""
        with open(filepath, "w") as f:
            f.write("=" * 80 + "\n")
            f.write("ShibaCuddles Network Scanner - Scan Results\n")
            f.write("=" * 80 + "\n\n")

            for result in results:
                if hasattr(result, "__dataclass_fields__"):
                    result_dict = asdict(result)
                else:
                    result_dict = result

                f.write(f"Host: {result_dict.get('ip', 'Unknown')}\n")
                f.write(f"Status: {'ALIVE' if result_dict.get('alive') else 'DEAD'}\n")

                open_ports = result_dict.get("open_ports", [])
                ports_str = ", ".join(map(str, open_ports)) if open_ports else "None"
                f.write(f"Open Ports: {ports_str}\n")

                services = result_dict.get("services", {})
                if services:
                    f.write("Services:\n")
                    for port, service_info in services.items():
                        service_name = service_info.get("name", "Unknown")
                        version = service_info.get("version", "")
                        f.write(f"  {port}: {service_name} {version}".strip() + "\n")

                os_info = result_dict.get("os_info", {})
                if os_info:
                    os_line = (
                        f"OS: {os_info.get('name', 'Unknown')} "
                        f"(Confidence: {os_info.get('confidence', 0)}%)"
                    )
                    f.write(os_line + "\n")

                scan_time = result_dict.get("scan_time", 0)
                try:
                    scan_time_str = f"{float(scan_time):.2f}s"
                except (TypeError, ValueError):
                    scan_time_str = str(scan_time)
                f.write(f"Scan Time: {scan_time_str}\n")
                f.write("-" * 80 + "\n\n")

    def generate_report(self, results: List) -> str:
        """
        Generate a detailed text report.

        Args:
            results: List of scan results

        Returns:
            Report string
        """
        report = []
        report.append("=" * 80)
        report.append("ShibaCuddles Network Scanner Report")
        report.append("=" * 80)
        report.append("")

        total_hosts = len(results)
        alive_hosts = sum(1 for r in results if getattr(r, "alive", False))
        total_open_ports = sum(len(getattr(r, "open_ports", [])) for r in results)

        report.append("SUMMARY")
        report.append("-" * 40)
        report.append(f"Total Hosts Scanned: {total_hosts}")
        report.append(f"Alive Hosts: {alive_hosts}")
        report.append(f"Dead Hosts: {total_hosts - alive_hosts}")
        report.append(f"Total Open Ports: {total_open_ports}")
        report.append("")

        report.append("HOST DETAILS")
        report.append("-" * 40)
        for result in results:
            if hasattr(result, "__dataclass_fields__"):
                result_dict = asdict(result)
            else:
                result_dict = result

            if result_dict.get("open_ports"):
                ip = result_dict.get("ip", "Unknown")
                ports = ", ".join(map(str, result_dict.get("open_ports", [])))
                report.append(f"{ip}: {ports}")

        report.append("")
        report.append("=" * 80)

        return "\n".join(report)
