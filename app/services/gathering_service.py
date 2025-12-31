from datetime import datetime, timezone
from typing import Optional
import json

class GatheringService:
    """
    Manages gathering mode state.
    When enabled, all requests are marked as legitimate without analysis.
    When disabled, automatically trains a new model with gathered data.
    """
    
    def __init__(self):
        self._is_gathering_mode = False
        self._gathering_started_at: Optional[datetime] = None
        self._requests_gathered = 0
    
    @property
    def is_gathering_mode(self) -> bool:
        return self._is_gathering_mode
    
    @property
    def gathering_started_at(self) -> Optional[datetime]:
        return self._gathering_started_at
    
    @property
    def requests_gathered(self) -> int:
        return self._requests_gathered
    
    def start_gathering(self):
        """Start gathering mode - mark all requests as legitimate"""
        self._is_gathering_mode = True
        self._gathering_started_at = datetime.now(timezone.utc)
        self._requests_gathered = 0
        print(f"✓ Gathering mode STARTED at {self._gathering_started_at}")
    
    def stop_gathering(self) -> dict:
        """Stop gathering mode and return stats"""
        if not self._is_gathering_mode:
            return {
                "was_gathering": False,
                "message": "Gathering mode was not active"
            }
        
        stats = {
            "was_gathering": True,
            "started_at": self._gathering_started_at,
            "stopped_at": datetime.now(timezone.utc),
            "requests_gathered": self._requests_gathered,
            "duration_seconds": (datetime.now(timezone.utc) - self._gathering_started_at).total_seconds()
        }
        
        # Reset state
        self._is_gathering_mode = False
        self._gathering_started_at = None
        self._requests_gathered = 0
        
        print(f"✓ Gathering mode STOPPED. Collected {stats['requests_gathered']} requests")
        return stats
    
    def increment_gathered_count(self):
        """Increment the count of gathered requests"""
        self._requests_gathered += 1
    
    def get_status(self) -> dict:
        """Get current gathering mode status"""
        return {
            "is_gathering_mode": self._is_gathering_mode,
            "gathering_started_at": self._gathering_started_at.isoformat() if self._gathering_started_at else None,
            "requests_gathered": self._requests_gathered,
            "duration_seconds": (datetime.now(timezone.utc) - self._gathering_started_at).total_seconds() 
                if self._gathering_started_at else 0
        }

# Global gathering service instance
gathering_service = GatheringService()