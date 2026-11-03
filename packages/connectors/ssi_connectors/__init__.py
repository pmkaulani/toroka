"""I/O adapters. Each returns a status the assessment can show: checked, could_not_check or not_checked.

Production note (blueprint 4.8): run the fetcher, OCR and image code in an isolated, egress-restricted worker.
In this repo they are plain functions behind interfaces so they can be tested and moved.
"""
