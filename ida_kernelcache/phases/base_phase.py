import logging
from abc import ABC, abstractmethod

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ida_kernelcache.kernelcache import KernelCache


class BasePhase(ABC):
    LOG_LEVEL = logging.INFO

    def __init__(self, kc: 'KernelCache'):
        self._kc = kc
        self.log = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def run(self):
        pass
