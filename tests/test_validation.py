import unittest

from securitywatchdaily.errors import ConfigValidationError
from securitywatchdaily.models import Platform, Source
from securitywatchdaily.validation import validate_platform, validate_source


class ValidationTests(unittest.TestCase):
    def test_platform_requires_keyword_family(self):
        with self.assertRaises(ConfigValidationError):
            validate_platform(Platform(id="valid_id", display_name="Valid"))

    def test_source_requires_valid_url_except_dynamic_msrc(self):
        validate_source(Source(id="msrc", name="MSRC", source_type="msrc", url=""))
        with self.assertRaises(ConfigValidationError):
            validate_source(Source(id="bad_source", name="Bad", source_type="cisa", url="not-url"))
        with self.assertRaises(ConfigValidationError):
            validate_source(Source(id="http_source", name="HTTP", source_type="cisa", url="http://example.com/feed.json"))


if __name__ == "__main__":
    unittest.main()
