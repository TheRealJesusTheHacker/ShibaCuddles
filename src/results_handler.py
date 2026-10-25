"""
Results handler for exporting scan results in multiple formats.
"""

import csv
import json
import logging
import os
import re
import xml.dom.minidom as minidom
import xml.etree.ElementTree as ET
from dataclasses import asdict
from typing import List

# Characters XML 1.0 forbids outright. Banners come from the network and
# are decoded with errors="ignore", which keeps legal-but-unprintable
# bytes (NUL, VT, unit separators, ...); a version string carrying one
# made the whole XML export fail ("not well-formed") while the JSON/TXT
# exports of the same results succeeded.
_XML_FORBIDDEN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _xml_safe(value) -> str:
    """Stringify a value with XML-1.0-forbidden characters removed."""
    return _XML_FORBIDDEN.sub("", str(value))


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
            # lexists, not exists: exists() follows symlinks, so a
            # planted DANGLING symlink at the output path read as "no
            # file there" and the writers below followed the link —
            # creating (or, for an existing target, the exists() check
            # was the only guard) the link's target despite
            # force=False. lexists sees the link itself. (A check-then-
            # open race remains in principle; closing it fully would
            # require reworking every writer to fd-based O_EXCL opens.)
            if not force and os.path.lexists(str(filepath)):
                raise FileExistsError(
                    f"Refusing to overwrite existing file: {filepath} "
                    "(pass force=True or use --force to overwrite)"
                )
            # Auto-detect format from file extension if not specified.
            # Case-insensitive: Windows users commonly have .CSV/.JSON/.XML.
            lowered = str(filepath).lower()
            if format == "json" and lowered.endswith(".csv"):
                format = "csv"
            elif format == "json" and lowered.endswith(".xml"):
                format = "xml"
            elif format == "json" and lowered.endswith(".txt"):
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

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(results_dict, f, indent=2)

    # CSV columns, in order. Fixed rather than derived from the first
    # row, so an empty result set still exports a valid header-only CSV:
    # previously _save_csv returned early on empty results and save()
    # reported success while writing no file at all.
    _CSV_FIELDS = ["ip", "alive", "open_ports", "port_count", "scan_time"]

    def _save_csv(self, results: List, filepath: str) -> None:
        """Save results as CSV."""
        rows = []
        for result in results:
            if hasattr(result, "__dataclass_fields__"):
                result_dict = asdict(result)
            else:
                result_dict = result

            open_ports = result_dict.get("open_ports") or []
            flat_row = {
                "ip": result_dict.get("ip", ""),
                "alive": result_dict.get("alive", ""),
                "open_ports": ",".join(map(str, open_ports)),
                "port_count": len(open_ports),
                "scan_time": result_dict.get("scan_time", ""),
            }
            rows.append(flat_row)

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self._CSV_FIELDS)
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
            host_elem.set("ip", _xml_safe(result_dict.get("ip", "")))
            host_elem.set("alive", _xml_safe(result_dict.get("alive", "")))

            open_ports_elem = ET.SubElement(host_elem, "OpenPorts")
            for port in result_dict.get("open_ports") or []:
                port_elem = ET.SubElement(open_ports_elem, "Port")
                port_elem.text = _xml_safe(port)

            udp_ports = result_dict.get("udp_open_ports") or []
            if udp_ports:
                udp_elem = ET.SubElement(host_elem, "UDPOpenPorts")
                for port in udp_ports:
                    port_elem = ET.SubElement(udp_elem, "Port")
                    port_elem.text = _xml_safe(port)

            services = result_dict.get("services", {})
            if services:
                services_elem = ET.SubElement(host_elem, "Services")
                for port, service_info in services.items():
                    service_elem = ET.SubElement(services_elem, "Service")
                    service_elem.set("port", _xml_safe(port))
                    service_elem.set(
                        "name", _xml_safe(service_info.get("name", "Unknown"))
                    )
                    if service_info.get("version"):
                        service_elem.set("version", _xml_safe(service_info["version"]))

            vulnerabilities = result_dict.get("vulnerabilities") or {}
            if vulnerabilities:
                vulns_elem = ET.SubElement(host_elem, "Vulnerabilities")
                for key, vuln in vulnerabilities.items():
                    vuln_elem = ET.SubElement(vulns_elem, "Vulnerability")
                    vuln_elem.set("service", _xml_safe(key))
                    vuln_elem.text = _xml_safe(vuln)

            if result_dict.get("scan_time"):
                time_elem = ET.SubElement(host_elem, "ScanTime")
                time_elem.text = _xml_safe(result_dict["scan_time"])

        xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(xml_str.split("\n")[1:]))

    def _save_txt(self, results: List, filepath: str) -> None:
        """Save results as human-readable text."""
        with open(filepath, "w", encoding="utf-8") as f:
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

                open_ports = result_dict.get("open_ports") or []
                ports_str = ", ".join(map(str, open_ports)) if open_ports else "None"
                f.write(f"Open Ports: {ports_str}\n")

                udp_ports = result_dict.get("udp_open_ports") or []
                if udp_ports:
                    f.write(f"UDP Open Ports: {', '.join(map(str, udp_ports))}\n")

                services = result_dict.get("services", {})
                if services:
                    f.write("Services:\n")
                    for port, service_info in services.items():
                        service_name = service_info.get("name", "Unknown")
                        version = service_info.get("version", "")
                        f.write(f"  {port}: {service_name} {version}".rstrip() + "\n")

                vulnerabilities = result_dict.get("vulnerabilities") or {}
                if vulnerabilities:
                    f.write(
                        "Vulnerabilities (bundled demo table — sample "
                        "data only, not a vulnerability feed):\n"
                    )
                    for key, vuln in vulnerabilities.items():
                        f.write(f"  {key}: {vuln}\n")

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
        # Summary counts must normalize dict results the same way the
        # exporters and the HOST DETAILS loop below do: getattr() on a
        # plain dict always falls back to the default, so dict inputs
        # (accepted everywhere else in this class) reported 0 alive
        # hosts and 0 open ports here even when the details section
        # listed the ports.
        normalized = [
            asdict(r) if hasattr(r, "__dataclass_fields__") else r for r in results
        ]
        alive_hosts = sum(
            1
            for r in normalized
            if (
                r.get("alive", False)
                if isinstance(r, dict)
                else getattr(r, "alive", False)
            )
        )
        total_open_ports = sum(
            (
                len(r.get("open_ports") or [])
                if isinstance(r, dict)
                else len(getattr(r, "open_ports", []) or [])
            )
            for r in normalized
        )

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
