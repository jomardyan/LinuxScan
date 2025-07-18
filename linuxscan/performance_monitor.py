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
"""

import time
import psutil
import threading
import logging
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
from collections import defaultdict, deque
import asyncio
import functools


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


class PerformanceMonitor:
    """Performance monitoring and optimization system"""
    
    def __init__(self, collection_interval: int = 5, history_size: int = 100):
        self.collection_interval = collection_interval
        self.history_size = history_size
        self.metrics_history: deque = deque(maxlen=history_size)
        self.function_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'call_count': 0,
            'total_time': 0.0,
            'avg_time': 0.0,
            'max_time': 0.0,
            'min_time': float('inf'),
            'last_call': None
        })
        self.is_monitoring = False
        self.monitor_thread = None
        self.logger = logging.getLogger(__name__)
        
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
                self.monitor_thread.join()
            self.logger.info("Performance monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                metrics = self._collect_metrics()
                self.metrics_history.append(metrics)
                self._check_thresholds(metrics)
                time.sleep(self.collection_interval)
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(1)
    
    def _collect_metrics(self) -> PerformanceMetrics:
        """Collect current system metrics"""
        # CPU and memory metrics
        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        # Network I/O metrics
        try:
            net_io = psutil.net_io_counters()
            network_io = {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            }
        except:
            network_io = {}
        
        # Disk I/O metrics
        try:
            disk_io = psutil.disk_io_counters()
            disk_metrics = {
                'read_bytes': disk_io.read_bytes,
                'write_bytes': disk_io.write_bytes,
                'read_count': disk_io.read_count,
                'write_count': disk_io.write_count
            } if disk_io else {}
        except:
            disk_metrics = {}
        
        # Thread count
        active_threads = threading.active_count()
        
        return PerformanceMetrics(
            timestamp=datetime.now(),
            cpu_usage=cpu_usage,
            memory_usage=memory.percent,
            memory_available=memory.available,
            network_io=network_io,
            disk_io=disk_metrics,
            active_threads=active_threads,
            function_calls=sum(stats['call_count'] for stats in self.function_stats.values()),
            response_time=0.0,  # Will be updated by function decorators
            scan_duration=0.0   # Will be updated by scan functions
        )
    
    def _check_thresholds(self, metrics: PerformanceMetrics):
        """Check if metrics exceed thresholds and log warnings"""
        if metrics.cpu_usage > self.thresholds['cpu_usage']:
            self.logger.warning(f"High CPU usage: {metrics.cpu_usage:.1f}%")
        
        if metrics.memory_usage > self.thresholds['memory_usage']:
            self.logger.warning(f"High memory usage: {metrics.memory_usage:.1f}%")
        
        if metrics.response_time > self.thresholds['response_time']:
            self.logger.warning(f"High response time: {metrics.response_time:.2f}s")
    
    def profile_function(self, func_name: Optional[str] = None):
        """Decorator to profile function performance"""
        def decorator(func):
            name = func_name or f"{func.__module__}.{func.__name__}"
            
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = func(*args, **kwargs)
                    return result
                finally:
                    duration = time.time() - start_time
                    self._update_function_stats(name, duration)
            
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = await func(*args, **kwargs)
                    return result
                finally:
                    duration = time.time() - start_time
                    self._update_function_stats(name, duration)
            
            return async_wrapper if asyncio.iscoroutinefunction(func) else wrapper
        return decorator
    
    def _update_function_stats(self, func_name: str, duration: float):
        """Update function performance statistics"""
        stats = self.function_stats[func_name]
        stats['call_count'] += 1
        stats['total_time'] += duration
        stats['avg_time'] = stats['total_time'] / stats['call_count']
        stats['max_time'] = max(stats['max_time'], duration)
        stats['min_time'] = min(stats['min_time'], duration)
        stats['last_call'] = datetime.now()
        
        # Check function performance threshold
        if duration > self.thresholds['function_time']:
            self.logger.warning(f"Slow function {func_name}: {duration:.2f}s")
    
    def cache_result(self, key: str, value: Any, ttl: Optional[int] = None):
        """Cache a result with optional TTL"""
        if len(self.cache) >= self.cache_max_size:
            # Simple LRU eviction - remove oldest entry
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
            self.cache_stats['evictions'] += 1
        
        cache_entry = {
            'value': value,
            'timestamp': datetime.now(),
            'ttl': ttl
        }
        
        self.cache[key] = cache_entry
    
    def get_cached_result(self, key: str) -> Optional[Any]:
        """Get cached result if available and not expired"""
        if key not in self.cache:
            self.cache_stats['misses'] += 1
            return None
        
        entry = self.cache[key]
        
        # Check TTL expiration
        if entry['ttl'] is not None:
            elapsed = (datetime.now() - entry['timestamp']).total_seconds()
            if elapsed > entry['ttl']:
                del self.cache[key]
                self.cache_stats['misses'] += 1
                return None
        
        self.cache_stats['hits'] += 1
        return entry['value']
    
    def cached_function(self, ttl: Optional[int] = None):
        """Decorator to cache function results"""
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                # Create cache key from function name and arguments
                cache_key = f"{func.__name__}:{hash(str(args) + str(sorted(kwargs.items())))}"
                
                # Try to get cached result
                cached_result = self.get_cached_result(cache_key)
                if cached_result is not None:
                    return cached_result
                
                # Execute function and cache result
                result = func(*args, **kwargs)
                self.cache_result(cache_key, result, ttl)
                return result
            
            return wrapper
        return decorator
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report"""
        if not self.metrics_history:
            return {'error': 'No metrics collected yet'}
        
        recent_metrics = list(self.metrics_history)[-10:]  # Last 10 measurements
        
        # Calculate averages for recent metrics
        avg_cpu = sum(m.cpu_usage for m in recent_metrics) / len(recent_metrics)
        avg_memory = sum(m.memory_usage for m in recent_metrics) / len(recent_metrics)
        avg_threads = sum(m.active_threads for m in recent_metrics) / len(recent_metrics)
        
        # Function performance summary
        function_summary = {}
        for func_name, stats in self.function_stats.items():
            if stats['call_count'] > 0:
                function_summary[func_name] = {
                    'calls': stats['call_count'],
                    'avg_time': stats['avg_time'],
                    'max_time': stats['max_time'],
                    'total_time': stats['total_time']
                }
        
        # Cache performance
        cache_hit_rate = 0
        if self.cache_stats['hits'] + self.cache_stats['misses'] > 0:
            cache_hit_rate = self.cache_stats['hits'] / (self.cache_stats['hits'] + self.cache_stats['misses'])
        
        return {
            'system_metrics': {
                'avg_cpu_usage': avg_cpu,
                'avg_memory_usage': avg_memory,
                'avg_active_threads': avg_threads,
                'current_cache_size': len(self.cache)
            },
            'function_performance': function_summary,
            'cache_performance': {
                'hit_rate': cache_hit_rate,
                'total_hits': self.cache_stats['hits'],
                'total_misses': self.cache_stats['misses'],
                'evictions': self.cache_stats['evictions']
            },
            'recommendations': self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate performance optimization recommendations"""
        recommendations = []
        
        if not self.metrics_history:
            return recommendations
        
        recent_metrics = list(self.metrics_history)[-10:]
        avg_cpu = sum(m.cpu_usage for m in recent_metrics) / len(recent_metrics)
        avg_memory = sum(m.memory_usage for m in recent_metrics) / len(recent_metrics)
        
        # CPU recommendations
        if avg_cpu > 80:
            recommendations.append("Consider reducing concurrent workers to lower CPU usage")
        
        # Memory recommendations
        if avg_memory > 85:
            recommendations.append("Consider implementing result streaming to reduce memory usage")
        
        # Function performance recommendations
        slow_functions = [name for name, stats in self.function_stats.items() 
                         if stats['avg_time'] > 1.0 and stats['call_count'] > 5]
        if slow_functions:
            recommendations.append(f"Optimize slow functions: {', '.join(slow_functions[:3])}")
        
        # Cache recommendations
        cache_hit_rate = 0
        if self.cache_stats['hits'] + self.cache_stats['misses'] > 0:
            cache_hit_rate = self.cache_stats['hits'] / (self.cache_stats['hits'] + self.cache_stats['misses'])
        
        if cache_hit_rate < 0.3:
            recommendations.append("Consider increasing cache size or TTL values")
        
        return recommendations
    
    def optimize_scan_performance(self, scan_config: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize scan configuration based on current system performance"""
        optimized_config = scan_config.copy()
        
        if not self.metrics_history:
            return optimized_config
        
        recent_metrics = list(self.metrics_history)[-3:]
        avg_cpu = sum(m.cpu_usage for m in recent_metrics) / len(recent_metrics)
        avg_memory = sum(m.memory_usage for m in recent_metrics) / len(recent_metrics)
        
        # Adjust max_workers based on system load
        current_workers = scan_config.get('max_workers', 100)
        
        if avg_cpu > 85 or avg_memory > 85:
            # Reduce workers if system is under high load
            optimized_config['max_workers'] = max(10, current_workers // 2)
            self.logger.info(f"Reduced max_workers to {optimized_config['max_workers']} due to high system load")
        elif avg_cpu < 30 and avg_memory < 50:
            # Increase workers if system has capacity
            optimized_config['max_workers'] = min(200, current_workers * 2)
            self.logger.info(f"Increased max_workers to {optimized_config['max_workers']} due to low system load")
        
        # Adjust timeout based on performance
        if avg_cpu > 80:
            optimized_config['timeout'] = scan_config.get('timeout', 30) * 1.5
        
        return optimized_config


# Global performance monitor instance
performance_monitor = PerformanceMonitor()