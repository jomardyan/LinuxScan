#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: Hayk Jomardyan
#
"""
Performance monitoring and optimization module
Enhanced with modern async patterns and comprehensive error handling
"""

import time
import psutil
import threading
import logging
import asyncio
import functools
from typing import Dict, List, Any, Optional, Callable, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict, deque
from contextlib import asynccontextmanager
import json

try:
    from .logging_config import get_logger, get_logging_manager
except ImportError:
    # Fallback for standalone usage
    import logging
    def get_logger(name: str = "performance") -> logging.Logger:
        return logging.getLogger(name)
    def get_logging_manager():
        return None


@dataclass
class PerformanceMetrics:
    """Container for performance metrics"""
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    memory_available: float
    network_io: Dict[str, int]
    disk_io: Dict[str, int]
    active_threads: int
    function_calls: int
    response_time: float
    scan_duration: float
    error_count: int = 0
    success_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for JSON serialization"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'cpu_usage': self.cpu_usage,
            'memory_usage': self.memory_usage,
            'memory_available': self.memory_available,
            'network_io': self.network_io,
            'disk_io': self.disk_io,
            'active_threads': self.active_threads,
            'function_calls': self.function_calls,
            'response_time': self.response_time,
            'scan_duration': self.scan_duration,
            'error_count': self.error_count,
            'success_count': self.success_count
        }


@dataclass
class FunctionMetrics:
    """Metrics for individual function calls"""
    name: str
    call_count: int = 0
    total_time: float = 0.0
    min_time: float = float('inf')
    max_time: float = 0.0
    error_count: int = 0
    last_called: Optional[datetime] = None
    
    @property
    def average_time(self) -> float:
        """Calculate average execution time"""
        return self.total_time / self.call_count if self.call_count > 0 else 0.0
    
    def update(self, execution_time: float, error: bool = False):
        """Update metrics with new execution data"""
        self.call_count += 1
        self.total_time += execution_time
        self.min_time = min(self.min_time, execution_time)
        self.max_time = max(self.max_time, execution_time)
        if error:
            self.error_count += 1
        self.last_called = datetime.now()


class PerformanceMonitor:
    """Performance monitoring and optimization system with async support"""
    
    def __init__(self, collection_interval: int = 5, history_size: int = 100):
        self.collection_interval = collection_interval
        self.history_size = history_size
        self.metrics_history: deque = deque(maxlen=history_size)
        self.function_metrics: Dict[str, FunctionMetrics] = {}
        self.is_monitoring = False
        self.monitor_thread = None
        self.logger = get_logger("performance")
        self.logging_manager = get_logging_manager()
        
        # Async monitoring support
        self._monitoring_task = None
        self._monitoring_event = asyncio.Event()
        
        # Cache for expensive operations
        self.cache = {}
        self.cache_stats = {'hits': 0, 'misses': 0, 'evictions': 0}
        self.cache_max_size = 1000
        
        # Performance thresholds
        self.thresholds = {
            'cpu_usage': 80.0,
            'memory_usage': 85.0,
            'response_time': 5.0,
            'function_time': 1.0
        }
        
        # Error tracking
        self.error_count = 0
        self.success_count = 0
    
    async def start_async_monitoring(self):
        """Start async performance monitoring"""
        if self._monitoring_task is None:
            self._monitoring_task = asyncio.create_task(self._async_monitor_loop())
            self.logger.info("Async performance monitoring started")
    
    async def stop_async_monitoring(self):
        """Stop async performance monitoring"""
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
            self._monitoring_task = None
            self.logger.info("Async performance monitoring stopped")
    
    async def _async_monitor_loop(self):
        """Async monitoring loop"""
        try:
            while True:
                try:
                    metrics = await self._collect_metrics_async()
                    self.metrics_history.append(metrics)
                    
                    # Check thresholds and log warnings
                    await self._check_thresholds_async(metrics)
                    
                    # Log metrics if logging manager is available
                    if self.logging_manager:
                        self.logging_manager.log_performance_metric(
                            "system_metrics", 
                            0,  # dummy value
                            cpu_usage=metrics.cpu_usage,
                            memory_usage=metrics.memory_usage,
                            active_threads=metrics.active_threads
                        )
                    
                    await asyncio.sleep(self.collection_interval)
                except Exception as e:
                    self.logger.error(f"Error in async monitoring loop: {e}")
                    await asyncio.sleep(self.collection_interval)
        except asyncio.CancelledError:
            self.logger.info("Async monitoring loop cancelled")
            raise
    
    async def _collect_metrics_async(self) -> PerformanceMetrics:
        """Collect performance metrics asynchronously"""
        loop = asyncio.get_event_loop()
        
        # Run CPU and memory collection in executor to avoid blocking
        cpu_usage = await loop.run_in_executor(None, psutil.cpu_percent)
        memory = await loop.run_in_executor(None, psutil.virtual_memory)
        
        # Get network and disk IO
        network_io = await loop.run_in_executor(None, psutil.net_io_counters)
        disk_io = await loop.run_in_executor(None, psutil.disk_io_counters)
        
        return PerformanceMetrics(
            timestamp=datetime.now(),
            cpu_usage=cpu_usage,
            memory_usage=memory.percent,
            memory_available=memory.available,
            network_io={
                'bytes_sent': network_io.bytes_sent if network_io else 0,
                'bytes_recv': network_io.bytes_recv if network_io else 0
            },
            disk_io={
                'read_bytes': disk_io.read_bytes if disk_io else 0,
                'write_bytes': disk_io.write_bytes if disk_io else 0
            },
            active_threads=threading.active_count(),
            function_calls=sum(m.call_count for m in self.function_metrics.values()),
            response_time=0.0,  # Will be updated by timing decorators
            scan_duration=0.0,  # Will be updated by scan operations
            error_count=self.error_count,
            success_count=self.success_count
        )
    
    async def _check_thresholds_async(self, metrics: PerformanceMetrics):
        """Check performance thresholds and log warnings"""
        if metrics.cpu_usage > self.thresholds['cpu_usage']:
            self.logger.warning(f"High CPU usage: {metrics.cpu_usage:.1f}%")
        
        if metrics.memory_usage > self.thresholds['memory_usage']:
            self.logger.warning(f"High memory usage: {metrics.memory_usage:.1f}%")
    
    def start_monitoring(self):
        """Start performance monitoring"""
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            self.logger.info("Performance monitoring started")
    
    def stop_monitoring(self):
        """Stop performance monitoring"""
        if self.is_monitoring:
            self.is_monitoring = False
            if self.monitor_thread:
                self.monitor_thread.join(timeout=1)
            self.logger.info("Performance monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                metrics = self._collect_metrics()
                self.metrics_history.append(metrics)
                
                # Check thresholds and log warnings
                self._check_thresholds(metrics)
                
                time.sleep(self.collection_interval)
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.collection_interval)
    
    def _collect_metrics(self) -> PerformanceMetrics:
        """Collect current performance metrics"""
        try:
            cpu_usage = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            network_io = psutil.net_io_counters()
            disk_io = psutil.disk_io_counters()
            
            return PerformanceMetrics(
                timestamp=datetime.now(),
                cpu_usage=cpu_usage,
                memory_usage=memory.percent,
                memory_available=memory.available,
                network_io={
                    'bytes_sent': network_io.bytes_sent if network_io else 0,
                    'bytes_recv': network_io.bytes_recv if network_io else 0
                },
                disk_io={
                    'read_bytes': disk_io.read_bytes if disk_io else 0,
                    'write_bytes': disk_io.write_bytes if disk_io else 0
                },
                active_threads=threading.active_count(),
                function_calls=sum(m.call_count for m in self.function_metrics.values()),
                response_time=0.0,
                scan_duration=0.0,
                error_count=self.error_count,
                success_count=self.success_count
            )
        except Exception as e:
            self.logger.error(f"Error collecting metrics: {e}")
            return PerformanceMetrics(
                timestamp=datetime.now(),
                cpu_usage=0.0,
                memory_usage=0.0,
                memory_available=0,
                network_io={},
                disk_io={},
                active_threads=0,
                function_calls=0,
                response_time=0.0,
                scan_duration=0.0,
                error_count=self.error_count,
                success_count=self.success_count
            )
    
    def _check_thresholds(self, metrics: PerformanceMetrics):
        """Check performance thresholds and log warnings"""
        if metrics.cpu_usage > self.thresholds['cpu_usage']:
            self.logger.warning(f"High CPU usage: {metrics.cpu_usage:.1f}%")
        
        if metrics.memory_usage > self.thresholds['memory_usage']:
            self.logger.warning(f"High memory usage: {metrics.memory_usage:.1f}%")
    
    def track_function_call(self, func_name: str, execution_time: float, error: bool = False):
        """Track function call metrics"""
        if func_name not in self.function_metrics:
            self.function_metrics[func_name] = FunctionMetrics(func_name)
        
        self.function_metrics[func_name].update(execution_time, error)
        
        # Update global counters
        if error:
            self.error_count += 1
        else:
            self.success_count += 1
        
        # Log performance metric
        if self.logging_manager:
            self.logging_manager.log_performance_metric(
                f"function_{func_name}",
                execution_time,
                error=error
            )
    
    def monitor_function(self, func: Callable = None, *, name: str = None):
        """Decorator to monitor function performance"""
        def decorator(f):
            func_name = name or f.__name__
            
            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                start_time = time.time()
                error = False
                try:
                    result = f(*args, **kwargs)
                    return result
                except Exception as e:
                    error = True
                    raise
                finally:
                    execution_time = time.time() - start_time
                    self.track_function_call(func_name, execution_time, error)
            
            return wrapper
        
        if func is None:
            return decorator
        else:
            return decorator(func)
    
    def monitor_async_function(self, func: Callable = None, *, name: str = None):
        """Decorator to monitor async function performance"""
        def decorator(f):
            func_name = name or f.__name__
            
            @functools.wraps(f)
            async def wrapper(*args, **kwargs):
                start_time = time.time()
                error = False
                try:
                    result = await f(*args, **kwargs)
                    return result
                except Exception as e:
                    error = True
                    raise
                finally:
                    execution_time = time.time() - start_time
                    self.track_function_call(func_name, execution_time, error)
            
            return wrapper
        
        if func is None:
            return decorator
        else:
            return decorator(func)
    
    @asynccontextmanager
    async def monitor_operation(self, operation_name: str):
        """Context manager for monitoring operation performance"""
        start_time = time.time()
        error = False
        try:
            yield
        except Exception as e:
            error = True
            raise
        finally:
            execution_time = time.time() - start_time
            self.track_function_call(operation_name, execution_time, error)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get performance metrics summary"""
        if not self.metrics_history:
            return {}
        
        latest = self.metrics_history[-1]
        
        # Calculate averages
        avg_cpu = sum(m.cpu_usage for m in self.metrics_history) / len(self.metrics_history)
        avg_memory = sum(m.memory_usage for m in self.metrics_history) / len(self.metrics_history)
        
        # Function metrics summary
        function_summary = {}
        for name, metrics in self.function_metrics.items():
            function_summary[name] = {
                'call_count': metrics.call_count,
                'average_time': metrics.average_time,
                'total_time': metrics.total_time,
                'error_rate': metrics.error_count / metrics.call_count if metrics.call_count > 0 else 0
            }
        
        return {
            'current_cpu': latest.cpu_usage,
            'current_memory': latest.memory_usage,
            'average_cpu': avg_cpu,
            'average_memory': avg_memory,
            'total_errors': self.error_count,
            'total_successes': self.success_count,
            'error_rate': self.error_count / (self.error_count + self.success_count) if (self.error_count + self.success_count) > 0 else 0,
            'active_threads': latest.active_threads,
            'function_metrics': function_summary,
            'cache_stats': self.cache_stats
        }
    
    def export_metrics(self, filename: str):
        """Export metrics to JSON file"""
        try:
            data = {
                'summary': self.get_metrics_summary(),
                'history': [m.to_dict() for m in self.metrics_history],
                'function_metrics': {
                    name: {
                        'call_count': m.call_count,
                        'total_time': m.total_time,
                        'average_time': m.average_time,
                        'min_time': m.min_time,
                        'max_time': m.max_time,
                        'error_count': m.error_count,
                        'last_called': m.last_called.isoformat() if m.last_called else None
                    }
                    for name, m in self.function_metrics.items()
                }
            }
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            self.logger.info(f"Metrics exported to {filename}")
        except Exception as e:
            self.logger.error(f"Failed to export metrics: {e}")


# Global performance monitor instance
_performance_monitor = None


def get_performance_monitor() -> PerformanceMonitor:
    """Get the global performance monitor instance"""
    global _performance_monitor
    if _performance_monitor is None:
        _performance_monitor = PerformanceMonitor()
    return _performance_monitor


# Decorators for easy use
def monitor_performance(func: Callable = None, *, name: str = None):
    """Decorator to monitor function performance"""
    monitor = get_performance_monitor()
    return monitor.monitor_function(func, name=name)


def monitor_async_performance(func: Callable = None, *, name: str = None):
    """Decorator to monitor async function performance"""
    monitor = get_performance_monitor()
    return monitor.monitor_async_function(func, name=name)
