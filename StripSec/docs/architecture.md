# StripSec Architecture

## Goal

Take a captured web-session dataset from a legal lab workflow and turn it into a short, readable report about downgrade risk and HTTPS hygiene.

## Current Flow

1. Load structured session data from JSON
2. Normalize pages, redirects, cookies, and embedded resources
3. Run detectors for:
   - downgrade redirects
   - missing HSTS
   - insecure session cookies
   - mixed content on HTTPS pages
4. Score the findings
5. Export JSON, Markdown, and HTML reports

## Why This Shape Works

This version is simple to test, easy to demo, and keeps the repo focused on analysis rather than attack simulation.
