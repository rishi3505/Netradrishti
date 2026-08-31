import uuid

def generate_uuid() -> uuid.UUID:
    """Generate a standard UUID4"""
    return uuid.uuid4()

def generate_uuid_str() -> str:
    """Generate a standard UUID4 as string"""
    return str(uuid.uuid4())
