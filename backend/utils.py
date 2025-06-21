import re

def slugify(text):
    text = re.sub(r'[^-\uFFFF\w\s-]', '', text).strip().lower()
    return re.sub(r'[-\s]+', '-', text) 