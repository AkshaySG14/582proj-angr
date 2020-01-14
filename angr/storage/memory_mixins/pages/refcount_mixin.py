import threading
from .. import MemoryMixin

class RefcountMixin(MemoryMixin):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.refcount = 1
        self.lock = threading.Lock()

    def acquire_unique(self):
        """
        Call this function to return a version of this page which can be used for writing, which may or may not
        be the same object as before. If you use this you must immediately replace the shared reference you previously
        had with the new unique copy.
        """
        with self.lock:
            if self.refcount == 1:
                return self
            else:
                self.refcount -= 1
                return self.copy({})

    def acquire_shared(self) -> None:
        """
        Call this function to indicate that this page has had a reference added to it and must be copied before it can
        be acquired uniquely again. Creating the object implicitly starts it with one shared reference.
        """
        with self.lock:
            self.refcount += 1

    def release_shared(self) -> None:
        """
        Call this function to indicate that this page has had a shared reference to it released
        """
        with self.lock:
            self.refcount -= 1

