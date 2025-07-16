from app.models import db, Log
from app.services.crypto_utils import sign_data
from datetime import datetime
import json

def create_log(user_id, action, details=None):
    log_data = {
        'user_id': user_id,
        'action': action,
        'details': details,
        'timestamp': datetime.utcnow().isoformat()
    }
    log_str = json.dumps(log_data, sort_keys=True).encode()
    signature = sign_data(log_str)
    log = Log(
        user_id=user_id,
        action=action,
        details=details,
        signature=signature
    )
    db.session.add(log)
    db.session.commit()
    return log 