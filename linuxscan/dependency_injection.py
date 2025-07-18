#!/usr/bin/env python3
"""
Dependency Injection System for LinuxScan
Modern dependency injection and factory patterns implementation
"""

import asyncio
import inspect
from typing import Any, Callable, Dict, Optional, Type, TypeVar, Union, get_type_hints
from functools import wraps
from dataclasses import dataclass
from abc import ABC, abstractmethod
import threading
import logging

try:
    from .logging_config import get_logger
except ImportError:
    def get_logger(name: str) -> logging.Logger:
        return logging.getLogger(name)

T = TypeVar('T')


class DependencyError(Exception):
    """Exception raised when dependency injection fails"""
    pass


@dataclass
class ServiceRegistration:
    """Registration information for a service"""
    service_type: Type
    implementation: Union[Type, Callable, Any]
    singleton: bool = False
    factory: Optional[Callable] = None
    dependencies: Optional[Dict[str, Type]] = None
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = {}


class DIContainer:
    """Dependency Injection Container"""
    
    def __init__(self):
        self._services: Dict[Type, ServiceRegistration] = {}
        self._instances: Dict[Type, Any] = {}
        self._lock = threading.RLock()
        self.logger = get_logger("dependency_injection")
    
    def register(
        self,
        service_type: Type[T],
        implementation: Union[Type[T], Callable[..., T], T] = None,
        singleton: bool = False,
        factory: Optional[Callable] = None
    ) -> 'DIContainer':
        """Register a service with the container"""
        with self._lock:
            if implementation is None:
                implementation = service_type
            
            # Auto-detect dependencies from type hints
            dependencies = self._extract_dependencies(implementation)
            
            registration = ServiceRegistration(
                service_type=service_type,
                implementation=implementation,
                singleton=singleton,
                factory=factory,
                dependencies=dependencies
            )
            
            self._services[service_type] = registration
            self.logger.debug(f"Registered service {service_type.__name__}")
            return self
    
    def register_singleton(
        self,
        service_type: Type[T],
        implementation: Union[Type[T], Callable[..., T], T] = None,
        factory: Optional[Callable] = None
    ) -> 'DIContainer':
        """Register a singleton service"""
        return self.register(service_type, implementation, singleton=True, factory=factory)
    
    def register_factory(
        self,
        service_type: Type[T],
        factory: Callable[..., T]
    ) -> 'DIContainer':
        """Register a factory function for creating services"""
        return self.register(service_type, factory, factory=factory)
    
    def register_instance(self, service_type: Type[T], instance: T) -> 'DIContainer':
        """Register a specific instance"""
        with self._lock:
            self._instances[service_type] = instance
            self.register(service_type, instance, singleton=True)
            return self
    
    def resolve(self, service_type: Type[T]) -> T:
        """Resolve a service from the container"""
        with self._lock:
            # Check if we have a cached instance
            if service_type in self._instances:
                return self._instances[service_type]
            
            # Check if service is registered
            if service_type not in self._services:
                raise DependencyError(f"Service {service_type.__name__} is not registered")
            
            registration = self._services[service_type]
            
            # Create instance
            instance = self._create_instance(registration)
            
            # Cache if singleton
            if registration.singleton:
                self._instances[service_type] = instance
            
            return instance
    
    async def resolve_async(self, service_type: Type[T]) -> T:
        """Resolve a service asynchronously"""
        # For now, just call the sync version
        # In the future, this could support async factories
        return self.resolve(service_type)
    
    def _create_instance(self, registration: ServiceRegistration) -> Any:
        """Create an instance of the service"""
        try:
            if registration.factory:
                # Use factory function
                return self._call_with_dependencies(registration.factory, registration.dependencies)
            
            elif callable(registration.implementation):
                if inspect.isclass(registration.implementation):
                    # Class constructor
                    return self._call_with_dependencies(registration.implementation, registration.dependencies)
                else:
                    # Factory function
                    return self._call_with_dependencies(registration.implementation, registration.dependencies)
            else:
                # Pre-created instance
                return registration.implementation
        
        except Exception as e:
            self.logger.error(f"Failed to create instance of {registration.service_type.__name__}: {e}")
            raise DependencyError(f"Failed to create instance of {registration.service_type.__name__}: {e}")
    
    def _call_with_dependencies(self, func: Callable, dependencies: Dict[str, Type]) -> Any:
        """Call a function with its dependencies resolved"""
        kwargs = {}
        
        # Resolve dependencies
        for param_name, param_type in dependencies.items():
            try:
                kwargs[param_name] = self.resolve(param_type)
            except DependencyError:
                # Try to resolve without the parameter if it's optional
                sig = inspect.signature(func)
                param = sig.parameters.get(param_name)
                if param and param.default is not inspect.Parameter.empty:
                    continue  # Skip optional parameter
                raise
        
        return func(**kwargs)
    
    def _extract_dependencies(self, implementation: Union[Type, Callable]) -> Dict[str, Type]:
        """Extract dependencies from function/class signature"""
        dependencies = {}
        
        try:
            if inspect.isclass(implementation):
                # Get constructor signature
                sig = inspect.signature(implementation.__init__)
                hints = get_type_hints(implementation.__init__)
            else:
                # Get function signature
                sig = inspect.signature(implementation)
                hints = get_type_hints(implementation)
            
            for param_name, param in sig.parameters.items():
                if param_name in ['self', 'cls']:
                    continue
                
                # Get type hint
                param_type = hints.get(param_name)
                if param_type and param_type != inspect.Parameter.empty:
                    dependencies[param_name] = param_type
        
        except Exception as e:
            self.logger.debug(f"Could not extract dependencies from {implementation}: {e}")
        
        return dependencies
    
    def clear(self):
        """Clear all registrations and instances"""
        with self._lock:
            self._services.clear()
            self._instances.clear()
    
    def is_registered(self, service_type: Type) -> bool:
        """Check if a service is registered"""
        return service_type in self._services


class ServiceProvider(ABC):
    """Abstract base class for service providers"""
    
    @abstractmethod
    def register_services(self, container: DIContainer):
        """Register services with the container"""
        pass


class LinuxScanServiceProvider(ServiceProvider):
    """Service provider for LinuxScan components"""
    
    def register_services(self, container: DIContainer):
        """Register LinuxScan services"""
        try:
            # Import here to avoid circular imports
            from .config import ConfigManager
            from .logging_config import LoggingManager
            from .performance_monitor import PerformanceMonitor
            
            # Register core services
            container.register_singleton(ConfigManager)
            container.register_singleton(LoggingManager)
            container.register_singleton(PerformanceMonitor)
            
            # Register scanner services
            try:
                from .enhanced_scanner import SecurityScanner
                container.register(SecurityScanner)
            except ImportError:
                pass
            
            # Register module services
            try:
                from .modules.base_scanner import BaseScannerModule
                container.register(BaseScannerModule)
            except ImportError:
                pass
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Error registering services: {e}")


# Global DI container
_container = None
_container_lock = threading.RLock()


def get_container() -> DIContainer:
    """Get the global DI container"""
    global _container
    with _container_lock:
        if _container is None:
            _container = DIContainer()
            # Register default services
            service_provider = LinuxScanServiceProvider()
            service_provider.register_services(_container)
        return _container


def inject(service_type: Type[T]) -> T:
    """Inject a dependency"""
    container = get_container()
    return container.resolve(service_type)


def inject_decorator(func: Callable = None, *, container: Optional[DIContainer] = None):
    """Decorator for automatic dependency injection"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Get container
            di_container = container or get_container()
            
            # Get function signature and type hints
            sig = inspect.signature(f)
            hints = get_type_hints(f)
            
            # Resolve dependencies
            for param_name, param in sig.parameters.items():
                if param_name in kwargs:
                    continue  # Already provided
                
                param_type = hints.get(param_name)
                if param_type and di_container.is_registered(param_type):
                    kwargs[param_name] = di_container.resolve(param_type)
            
            return f(*args, **kwargs)
        
        return wrapper
    
    if func is None:
        return decorator
    else:
        return decorator(func)


def inject_async_decorator(func: Callable = None, *, container: Optional[DIContainer] = None):
    """Decorator for automatic dependency injection in async functions"""
    def decorator(f):
        @wraps(f)
        async def wrapper(*args, **kwargs):
            # Get container
            di_container = container or get_container()
            
            # Get function signature and type hints
            sig = inspect.signature(f)
            hints = get_type_hints(f)
            
            # Resolve dependencies
            for param_name, param in sig.parameters.items():
                if param_name in kwargs:
                    continue  # Already provided
                
                param_type = hints.get(param_name)
                if param_type and di_container.is_registered(param_type):
                    kwargs[param_name] = await di_container.resolve_async(param_type)
            
            return await f(*args, **kwargs)
        
        return wrapper
    
    if func is None:
        return decorator
    else:
        return decorator(func)


# Context manager for scoped containers
class ScopedContainer:
    """Context manager for scoped dependency injection"""
    
    def __init__(self, parent_container: Optional[DIContainer] = None):
        self.parent_container = parent_container or get_container()
        self.scoped_container = DIContainer()
        self.old_container = None
    
    def __enter__(self) -> DIContainer:
        # Copy registrations from parent
        with self.parent_container._lock:
            for service_type, registration in self.parent_container._services.items():
                self.scoped_container._services[service_type] = registration
        
        return self.scoped_container
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Clean up scoped instances
        self.scoped_container.clear()