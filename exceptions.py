def response_code_exception(response):
    if response is None:
        return UnknownError("No response returned.")
    if response.status_code >= 200 and response.status_code < 300:
        return None
    
    msg = response.text
    if response.status_code >= 400 and response.status_code < 404:
        return ValidationError(msg)
    if response.status_code == 404:
        return NotFoundError(msg)
    if response.status_code == 409:
        return ConflictError(msg)
    return UnknownError(msg)

class ValidationError(Exception):
    pass

class NotFoundError(Exception):
    pass

class ConflictError(Exception):
    pass

class UnknownError(Exception):
    pass