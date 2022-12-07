import time
from datetime import datetime, timezone, timedelta

end = datetime.utcnow().replace(tzinfo=timezone.utc)
start = end - timedelta(days=30)
print(start.timestamp(), start)
print(end.timestamp(), end)


now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
print(now)

startDateTime = (datetime.now(timezone.utc) - timedelta(days=31)).strftime(
    "%Y-%m-%dT%H:%M:%SZ"
)
print(startDateTime)
