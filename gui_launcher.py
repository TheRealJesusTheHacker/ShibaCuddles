#!/usr/bin/env python3
"""
ShibaCuddles GUI Launcher
Starts the graphical interface for the network scanner.
"""

import sys
import logging
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.utils import setup_logging, print_banner

def main():
    """Launch GUI application."""
    print_banner()
    
    # Setup logging
    logger = setup_logging(logging.INFO)
    logger.info("Starting ShibaCuddles GUI")
    
    try:
        from gui.main_window import main as gui_main
        gui_main()
    except ImportError:
        logger.error(
            "PyQt6 not installed. Install with:\n"
            "  pip install PyQt6 PyQt6-Charts"
        )
        sys.exit(1)
    except SystemExit as e:
        # gui/main_window.py calls sys.exit(1) at import time when PyQt6 is
        # missing; SystemExit is not an Exception subclass, so without this
        # handler the friendly message above would never print.
        if e.code:
            logger.error(
                "PyQt6 not installed. Install with:\n"
                "  pip install PyQt6 PyQt6-Charts"
            )
        sys.exit(e.code if isinstance(e.code, int) else 1)
    except Exception as e:
        logger.error(f"GUI startup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
