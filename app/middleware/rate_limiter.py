import logging
import time
from collections import defaultdict, deque

log = logging.getLogger("security")


class SlidingWindowLimiter:
    def __init__(self, max_requests=30, window_seconds=60, block_seconds=300):
        self.max_requests, self.window_seconds, self.block_seconds = max_requests, window_seconds, block_seconds
        self.requests = defaultdict(deque)
        self.blocked_until = {}

    def is_blocked(self, ip):
        return self.blocked_until.get(ip, 0) > time.monotonic()

    def allow(self, ip):
        now = time.monotonic()
        queue = self.requests[ip]
        while queue and queue[0] <= now - self.window_seconds:
            queue.popleft()
        if len(queue) >= self.max_requests:
            log.warning("rate limit exceeded ip=%s", ip)
            return False
        queue.append(now)
        return True

    def retry_after(self, ip):
        queue = self.requests[ip]
        return max(1, int(self.window_seconds - (time.monotonic() - queue[0]))) if queue else 1

    def greylist(self, ip):
        self.blocked_until[ip] = time.monotonic() + self.block_seconds
        log.warning("WAF greylist ip=%s duration=%ss", ip, self.block_seconds)


limiter = SlidingWindowLimiter()
