
from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

def save_uploaded_file(uploaded_file: FileStorage, upload_folder: str) -> str:
    upload_dir = Path(upload_folder)
    upload_dir.mkdir(parents=True, exist_ok=True)
    original_name = secure_filename(uploaded_file.filename or "evidence.bin")
    filename = f"{uuid4().hex}_{original_name}"
    path = upload_dir / filename
    uploaded_file.save(path)
    return str(path)
