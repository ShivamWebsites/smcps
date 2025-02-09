from datetime import datetime
from bson import ObjectId

class Content:
    def __init__(self, title, content_type, script, user_id):
        self.title = title
        self.content_type = content_type
        self.script = script
        self.user_id = user_id
        self.created_at = datetime.utcnow()
        self.status = 'draft'
        self.qc_status = 'pending'
        self.qc_feedback = []
        self.storyboard = None

    def to_dict(self):
        return {
            'title': self.title,
            'content_type': self.content_type,
            'script': self.script,
            'user_id': self.user_id,
            'created_at': self.created_at,
            'status': self.status,
            'qc_status': self.qc_status,
            'qc_feedback': self.qc_feedback,
            'storyboard': self.storyboard
        }