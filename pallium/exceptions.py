class UserFriendlyException(Exception):
    """No traceback is shown for this type of exception."""
    pass


class ProfileNotFoundError(UserFriendlyException):
    pass


class SessionNotFoundError(UserFriendlyException):
    pass


class NetnsNotFoundError(UserFriendlyException):
    pass


class ProfileAlreadyRunningException(UserFriendlyException):
    pass


class SessionCreationException(UserFriendlyException):
    pass


class ConfigurationError(UserFriendlyException):
    pass


class DuplicateBridgeException(UserFriendlyException):
    pass


class InterfaceNotFoundException(UserFriendlyException):
    pass


class DependencyNotFoundException(UserFriendlyException):
    pass
