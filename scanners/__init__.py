"""
Multi-Ecosystem Malicious Package Scanner Modules
"""

__version__ = "1.0.0"

# Export main modules
from scanners import ecosystem_detector
from scanners import dependency_parsers
from scanners import file_input_parser
from scanners import malicious_checker
from scanners import report_generator
from scanners import ioc_detector

__all__ = [
    'ecosystem_detector',
    'dependency_parsers',
    'file_input_parser',
    'malicious_checker',
    'report_generator',
    'ioc_detector',
]

