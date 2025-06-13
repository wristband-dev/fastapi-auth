class WristbandError(Exception):
    def __init__(self, error: str, error_description: str = "") -> None:
        super().__init__(f"{error}: {error_description}")
        self.error = error
        self.error_description = error_description

    def get_error(self) -> str:
        return self.error

    def get_error_description(self) -> str:
        return self.error_description


class InvalidGrantError(WristbandError):
    def __init__(self, error_description: str = "") -> None:
        super().__init__("invalid_grant", error_description)
