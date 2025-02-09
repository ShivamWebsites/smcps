from datetime import datetime
from bson import ObjectId

class Trend:
    def __init__(self, title, platform, engagement_metrics, sentiment_score=None):
        self.title = title
        self.platform = platform
        self.engagement_metrics = engagement_metrics
        self.sentiment_score = sentiment_score
        self.created_at = datetime.utcnow()
        self.status = 'active'
        self.roi_potential = None

    def to_dict(self):
        return {
            'title': self.title,
            'platform': self.platform,
            'engagement_metrics': self.engagement_metrics,
            'sentiment_score': self.sentiment_score,
            'created_at': self.created_at,
            'status': self.status,
            'roi_potential': self.roi_potential
        }