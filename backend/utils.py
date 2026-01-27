import re
from backend.config_manager import ALLOWED_EXTENSIONS

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def secure_filename(filename):
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)
