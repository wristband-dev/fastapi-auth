from enum import Enum

class CallbackResultType(Enum):
    """
    Enum representing the result type of a callback.
    """
    COMPLETED = 'COMPLETED'
    REDIRECT_REQUIRED = 'REDIRECT_REQUIRED'