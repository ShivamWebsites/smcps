from datetime import datetime
from bson import ObjectId

class User:
    def __init__(self, email, password, confirm_password,  full_name, role='user', status='active', business_name=None, profile_picture=None):
        # Validate that password and confirm_password match
        if password != confirm_password:
            raise ValueError("Passwords do not match")
        
        self.email = email
        self.password = password  # Should be hashed before storing
        self.full_name = full_name
        self.role = role
        self.status = status
        self.business_name = business_name
        self.profile_picture = profile_picture
        self.created_at = datetime.utcnow()
        self.preferences = {
            'content_types': [],
            'themes': [],
            'platforms': [],
            'audience': {}
        }

    def to_dict(self):
        return {
            'email': self.email,
            'full_name': self.full_name,
            'role': self.role,
            'status': self.status,
            'business_name': self.business_name,
            'profile_picture': self.profile_picture,
            'created_at': self.created_at,
            'preferences': self.preferences
        }

    def is_admin(self):
        """ Check if the user is an admin. """
        return self.role == 'admin'

    def is_user(self):
        """ Check if the user is a regular user. """
        return self.role == 'user'

    def set_role(self, role):
        """ Set the role of the user. """
        if role in ['admin', 'user']:
            self.role = role
        else:
            raise ValueError("Role must be 'admin' or 'user'")
        
    def set_status(self, status):
        """ Set the status of the user. """
        if status in ['active', 'blocked', 'inactive']:
            self.status = status
        else:
            raise ValueError("Status must be 'active', 'blocked', or 'inactive'")

    def is_active(self):
        """ Check if the user is active. """
        return self.status == 'active'

    def is_blocked(self):
        """ Check if the user is blocked. """
        return self.status == 'blocked'
