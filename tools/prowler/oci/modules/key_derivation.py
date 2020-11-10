# Implementation of S3 key derivation algorithm for validation purposes

import hashlib
import hmac
import base64


def HmacSHA256(message, key):
    msg_bytes = message.encode('utf-8')
    digest = hmac.new(key, msg_bytes, digestmod=hashlib.sha256).digest()
    return digest


def generate_derived_key(secret_key, date, region, service_name):
    secret_key_bytes = ("AWS4" + secret_key).encode('utf-8')

    date_bytes = HmacSHA256(date, secret_key_bytes)
    region_bytes = HmacSHA256(region, date_bytes)
    service_bytes = HmacSHA256(service_name, region_bytes)
    derived_key_bytes = HmacSHA256("aws4_request", service_bytes)

    derived_key = base64.b64encode(derived_key_bytes).decode()
    return derived_key


def is_derived_key_valid(key_val, date, region, service, secret_key):
    ref_key_val = generate_derived_key(secret_key, date, region, service)
    return key_val == ref_key_val