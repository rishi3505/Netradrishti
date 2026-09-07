from abc import ABC, abstractmethod
from typing import Any, Optional

class BaseNormalizer(ABC):
    @abstractmethod
    def normalize(self, value: Any) -> Optional[Any]:
        """Normalize a field value"""
        pass
