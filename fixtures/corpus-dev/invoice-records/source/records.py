"""Original DEV fixture: dataclass fields and inherited methods."""

from dataclasses import dataclass
from decimal import Decimal

CURRENCY = "USD"


@dataclass(frozen=True)
class Record:
    number: str

    def identifier(self):
        return self.number


@dataclass(frozen=True)
class Invoice(Record):
    amount: Decimal
    tax: Decimal

    def total(self):
        return self.amount + self.tax
