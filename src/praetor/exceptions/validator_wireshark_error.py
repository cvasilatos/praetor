"""Module for Wireshark-related validation errors.

This module provides the ValidatorWiresharkError exception class for handling
errors that occur during protocol validation with Wireshark parsing.
"""

from praetor.exceptions.base_error import BaseError


class ValidatorWiresharkError(BaseError):
    """Error class for protocol validation errors related to Wireshark parsing."""
