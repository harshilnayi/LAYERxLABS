# StripSec Architecture

## Goal

Take a captured web-session dataset from a legal lab workflow and turn it into a readable report about downgrade risk, session exposure, and browser-side protection gaps.

## Current Flow

1. Load either structured JSON session data or HAR exports from a browser workflow
2. Normalize pages, methods, headers, cookies, request cookies, and embedded resources
3. Run detectors for:
   - downgrade redirects
   - sensitive submissions over HTTP
   - sensitive values in query strings
   - missing HSTS
   - insecure session cookies
   - weak cookie scope
   - mixed content on HTTPS pages
   - missing CSP and Referrer-Policy
4. Score the findings into a simple risk summary
5. Export JSON, Markdown, and HTML reports with evidence and recommendations

## Detection Model

`StripSec` treats each captured request or response as a page record. That record keeps together:

- the URL and method
- normalized response headers
- normalized request headers
- response cookies and request cookies
- embedded resources when the structured fixture provides them
- form fields and request bodies when the capture includes them

That gives the detectors enough context to answer a few practical questions:

- did an HTTPS flow point the browser back to HTTP
- did sensitive data move over plain HTTP
- are session cookies protected the way we would expect
- are the browser-side headers doing their part

## Reporting Shape

The reporting layer does not just dump findings. It also rolls up:

- how many domains were seen
- how much of the capture stayed on HTTPS
- how many downgrade paths were observed
- how often core protections like HSTS and CSP appeared

That keeps the output readable even when the raw finding list grows.

## Why This Shape Works

This shape keeps the project easy to test, easy to extend, and focused on analysis rather than simulation. It is also flexible enough to accept both hand-built fixtures and browser-exported captures without changing the detector model.
