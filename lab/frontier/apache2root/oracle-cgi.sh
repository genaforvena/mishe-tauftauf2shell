#!/bin/sh
# CGI endpoint for the CVE-2026-119618 CONTENT_LENGTH oracle.
# Prints exactly what mod_cgi derived from request_rec->headers_in.
printf 'Content-Type: text/plain\r\n\r\n'
printf 'CONTENT_LENGTH=[%s]\n' "${CONTENT_LENGTH-<UNSET>}"
printf 'CONTENT_TYPE=[%s]\n' "${CONTENT_TYPE-<UNSET>}"
