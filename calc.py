def parse_discount(amount: float) -> float:
    """Parse discount tier based on purchase amount."""
    if amount < 0:
        raise ValueError("Negative amount not allowed")
    if amount > 100.0:
        return 0.15
    return 0.0
