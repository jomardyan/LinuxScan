#!/usr/bin/env python3
"""
LinuxScan Logging Configuration
Structured logging implementation for comprehensive error handling and monitoring
"""

import logging
import logging.handlers
import json
import time
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
import os


class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured logging with JSON output"""
    
    def format(self, record):
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'thread': record.thread,
            'process': record.process,
        }
        
        # Add exception information if present
        if record.exc_info:
            log_entry['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': self.formatException(record.exc_info)
            }
        
        # Add custom fields from extra
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 
                          'filename', 'module', 'exc_info', 'exc_text', 'stack_info',
                          'lineno', 'funcName', 'created', 'msecs', 'relativeCreated',
                          'thread', 'threadName', 'processName', 'process', 'message']:
                log_entry[key] = value
        
        return json.dumps(log_entry, default=str)


class LoggingManager:
    """Centralized logging management for LinuxScan"""
    
    def __init__(self, log_dir: str = "/tmp/linuxscan_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.loggers = {}
        self.setup_logging()
    
    def setup_logging(self):
        """Setup structured logging configuration"""
        # Create formatters
        self.structured_formatter = StructuredFormatter()
        self.simple_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Setup root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
        
        # Clear existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # File handler for structured logs
        log_file = self.log_dir / "linuxscan.log"
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10*1024*1024, backupCount=5
        )
        file_handler.setFormatter(self.structured_formatter)
        file_handler.setLevel(logging.INFO)
        root_logger.addHandler(file_handler)
        
        # Console handler for simple output
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(self.simple_formatter)
        console_handler.setLevel(logging.WARNING)
        root_logger.addHandler(console_handler)
        
        # Error log file
        error_file = self.log_dir / "errors.log"
        error_handler = logging.handlers.RotatingFileHandler(
            error_file, maxBytes=10*1024*1024, backupCount=5
        )
        error_handler.setFormatter(self.structured_formatter)
        error_handler.setLevel(logging.ERROR)
        root_logger.addHandler(error_handler)
    
    def get_logger(self, name: str) -> logging.Logger:
        """Get or create a logger with the given name"""
        if name not in self.loggers:
            logger = logging.getLogger(name)
            self.loggers[name] = logger
        return self.loggers[name]
    
    def log_scan_start(self, scan_type: str, target: str, **kwargs):
        """Log scan start with structured data"""
        logger = self.get_logger("linuxscan.scan")
        logger.info(
            f"Starting {scan_type} scan on {target}",
            extra={
                'event_type': 'scan_start',
                'scan_type': scan_type,
                'target': target,
                'scan_parameters': kwargs
            }
        )
    
    def log_scan_complete(self, scan_type: str, target: str, duration: float, results: Dict[str, Any]):
        """Log scan completion with results summary"""
        logger = self.get_logger("linuxscan.scan")
        logger.info(
            f"Completed {scan_type} scan on {target} in {duration:.2f}s",
            extra={
                'event_type': 'scan_complete',
                'scan_type': scan_type,
                'target': target,
                'duration': duration,
                'results_summary': self._summarize_results(results)
            }
        )
    
    def log_scan_error(self, scan_type: str, target: str, error: Exception, **kwargs):
        """Log scan error with context"""
        logger = self.get_logger("linuxscan.scan")
        logger.error(
            f"Error in {scan_type} scan on {target}: {error}",
            extra={
                'event_type': 'scan_error',
                'scan_type': scan_type,
                'target': target,
                'error_type': type(error).__name__,
                'error_message': str(error),
                'context': kwargs
            },
            exc_info=True
        )
    
    def log_performance_metric(self, metric_name: str, value: float, **kwargs):
        """Log performance metrics"""
        logger = self.get_logger("linuxscan.performance")
        logger.info(
            f"Performance metric: {metric_name} = {value}",
            extra={
                'event_type': 'performance_metric',
                'metric_name': metric_name,
                'metric_value': value,
                'metadata': kwargs
            }
        )
    
    def log_security_event(self, event_type: str, severity: str, description: str, **kwargs):
        """Log security events"""
        logger = self.get_logger("linuxscan.security")
        logger.warning(
            f"Security event: {event_type} - {description}",
            extra={
                'event_type': 'security_event',
                'security_event_type': event_type,
                'severity': severity,
                'description': description,
                'details': kwargs
            }
        )
    
    def _summarize_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Create a summary of scan results"""
        summary = {}
        
        if isinstance(results, dict):
            for key, value in results.items():
                if isinstance(value, list):
                    summary[f"{key}_count"] = len(value)
                elif isinstance(value, dict):
                    summary[f"{key}_keys"] = list(value.keys())
                else:
                    summary[key] = value
        
        return summary


# Global logging manager instance
_logging_manager = None


def get_logger(name: str = "linuxscan") -> logging.Logger:
    """Get a logger instance with structured logging configured"""
    global _logging_manager
    if _logging_manager is None:
        _logging_manager = LoggingManager()
    return _logging_manager.get_logger(name)


def get_logging_manager() -> LoggingManager:
    """Get the global logging manager instance"""
    global _logging_manager
    if _logging_manager is None:
        _logging_manager = LoggingManager()
    return _logging_manager


# Context manager for logging scan operations
class LoggedOperation:
    """Context manager for logging scan operations with timing"""
    
    def __init__(self, operation_name: str, target: str, logger: Optional[logging.Logger] = None):
        self.operation_name = operation_name
        self.target = target
        self.logger = logger or get_logger("linuxscan.operations")
        self.start_time = None
        self.logging_manager = get_logging_manager()
    
    def __enter__(self):
        self.start_time = time.time()
        self.logging_manager.log_scan_start(self.operation_name, self.target)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        
        if exc_type is not None:
            self.logging_manager.log_scan_error(
                self.operation_name, self.target, exc_val,
                duration=duration
            )
        else:
            self.logging_manager.log_scan_complete(
                self.operation_name, self.target, duration, {}
            )
        
        return False  # Don't suppress exceptions