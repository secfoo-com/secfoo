"""Stand-in for a vulnerable dependency, used by the #73 conformance kit."""


def parse(text):
    """The "vulnerable" function the kit's watchlist names."""
    return text[::-1]


def safe(text):
    return text
