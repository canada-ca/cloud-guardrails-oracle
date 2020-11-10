import base64
import contextlib
import email
import enum
import hashlib
import logging
import time
import uuid
import urllib.parse

import httpsig
import requests

RETRY_LOG = logging.getLogger("retry")
WIRE_LOG = logging.getLogger("wire")

EXPECTED = []
BACKOFF = []
MAX_BACKOFF = 64  # Total time to take when retrying calls
INITIAL_BACKOFF = 1  # Backoff duration doubles every time


@contextlib.contextmanager
def http_retry(expect, max_backoff=None):
    """
    Load an expected status onto the retry stack.

    expect should be a `modules.Status` instance (ie. Status.OK)
    """
    EXPECTED.append(expect)
    if max_backoff:
        BACKOFF.append(max_backoff)

    try:
        yield
    finally:
        EXPECTED.pop()
        if max_backoff:
            BACKOFF.pop()


class Status(enum.Enum):
    # HTTP codes
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NO_CONTENT = 204
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    NOT_ALLOWED = 405
    REQUEST_TIMEOUT = 408
    CONFLICT = 409
    PRECONDITION_FAILED = 412
    UNSUPPORTED_MEDIA_TYPE = 415
    TOO_MANY_REQUESTS = 429
    SERVER_ERROR = 500
    SERVICE_UNAVAILABLE = 503

    # Service codes
    USER_ADD_SUCCESS = 201
    USER_AUTH_SUCCESS = 200
    USER_AUTH_FAILURE = 400
    USER_AUTH_TIMEOUT = 30


class SignedRequestAuth(requests.auth.AuthBase):
    """A requests auth instance that can be reused across requests"""
    generic_headers = ["date", "(request-target)", "host"]
    body_headers = ["content-length", "content-type", "x-content-sha256"]
    required_headers = {
        "options": [],
        "get": generic_headers,
        "head": generic_headers,
        "delete": generic_headers,
        "put": generic_headers + body_headers,
        "post": generic_headers + body_headers
    }

    def __init__(self, key_id, private_key,
                 cross_tenancy_intent=None,
                 cross_tenancy_intent_as_signed_header=True,
                 obo_call=False,
                 sign_request_id=False):
        # Build a httpsig.requests_auth.HTTPSignatureAuth for each
        # HTTP method's required headers
        self.signers = {}
        self.cross_tenancy_intent = cross_tenancy_intent
        self.obo_call = obo_call
        for method in self.required_headers:
            method_headers = self.required_headers[method][:]
            if sign_request_id:
                method_headers.append('opc-request-id')
            if cross_tenancy_intent is not None and cross_tenancy_intent_as_signed_header:
                method_headers.append("X-Cross-Tenancy-Request")
            if obo_call:
                method_headers.append('opc-obo-token')
            signer = httpsig.sign.HeaderSigner(
                key_id=key_id, secret=private_key, algorithm="rsa-sha256", headers=method_headers)
            use_host = "host" in method_headers
            self.signers[method] = (signer, use_host)

    def inject_missing_headers(self, request, sign_body):
        # Inject date if missing
        request.headers.setdefault("date", email.utils.formatdate(usegmt=True))

        if self.cross_tenancy_intent is not None:
            request.headers["x-cross-TENANCY-request"] = self.cross_tenancy_intent

        # Requests with a body need to send content-type,
        # content-length, and x-content-sha256
        if sign_body:
            request.headers.setdefault("content-type", "application/json")
            body = request.body
            if body is None:
                body = ""
            if "x-content-sha256" not in request.headers:
                m = hashlib.sha256(body.encode("utf-8"))
                base64digest = base64.b64encode(m.digest())
                base64string = base64digest.decode("utf-8")
                request.headers["x-content-sha256"] = base64string
            request.headers.setdefault("content-length", len(body))

    def __call__(self, request):
        verb = request.method.lower()
        signer, use_host = self.signers.get(verb, (None, None))
        if signer is None:
            raise ValueError("Don't know how to sign request verb {}".format(verb))

        # Inject body headers for put/post requests, date for all requests
        sign_body = verb in ["put", "post"]
        self.inject_missing_headers(request, sign_body=sign_body)

        if use_host:
            host = urllib.parse.urlparse(request.url).netloc
        else:
            host = None
        signed_headers = signer.sign(request.headers, host=host, method=request.method, path=request.path_url)
        request.headers.update(signed_headers)
        return request


class Session(requests.Session):
    def send(self, request, **kwargs):
        if not EXPECTED:
            return self._single_send(request, **kwargs)
        return self._with_retries(EXPECTED[-1], request, **kwargs)

    def _single_send(self, request, **kwargs):
        _log_request(request)
        response = super().send(request, **kwargs)
        WIRE_LOG.debug("===")
        _log_response(response)
        return response

    def _with_retries(self, expected_status, request, **kwargs):
        calls = 0
        if not BACKOFF:
            remaining_backoff = MAX_BACKOFF
        else:
            remaining_backoff = BACKOFF[-1]
        backoff = INITIAL_BACKOFF

        if request.method == 'POST':

            add_retry_token(request.headers)

        while True:
            calls += 1

            RETRY_LOG.debug("Call {} expecting {}({})".format(calls, expected_status, expected_status.value))

            try:
                response = self._single_send(request, **kwargs)
            except Exception:
                response = None
                RETRY_LOG.warning("Exception while calling requests", exc_info=True)
            if response is not None:
                if response.status_code == expected_status.value:
                    RETRY_LOG.debug("Success after {} calls".format(calls))
                    return response
                else:
                    RETRY_LOG.debug("Call {} expected {}({}) but got {}".format(
                        calls, expected_status, expected_status.value,
                        response.status_code))
            else:
                RETRY_LOG.debug("Call {} failed without response".format(calls))

            # Next call can't retry
            if remaining_backoff <= 0:
                break

            # Sleep and try again
            backoff = min(2 * backoff, remaining_backoff)
            remaining_backoff -= backoff
            time.sleep(backoff)
        message = "Retry wrapper failed after {} calls".format(calls)
        RETRY_LOG.warning(message)
        raise RuntimeError(message)


def _logger(prefix, offset=1):
    def log(string=""):
        WIRE_LOG.debug("{}{}{}".format(prefix, " " * log.offset, string).strip())
    log.offset = offset
    return log


def _log_request(request):
    log = _logger(">>>")
    log("{} {}".format(request.method, request.url))
    log.offset += 2
    for name, value in sorted(request.headers.items()):
        log("{}: {}".format(name, value))
    log()
    log(request.body or "(no body)")


def _log_response(response):
    log = _logger("<<<")
    log("{} {}".format(response.status_code, response.reason))
    log.offset += 2
    for name, value in sorted(response.headers.items()):
        log("{}: {}".format(name, value))
    log()
    if not response.text:
        log("(no body)")
    for line in response.text.split("\n"):
        log(line)


def monkeypatch_requests():
    """
    This patches requests.Session so that we get logging/retries everywhere without using special imports.

    This function must be called before any other module imports requests.
    """
    # requests/__init__ stores a reference `from .sessions import Session`
    requests.Session = Session
    # requests/api import sessions `from . import sessions`
    requests.sessions.Session = Session


def add_retry_token(headers):

    if "opc-retry-token" in headers:  # if the token is already there
        return headers  # do nothing

    headers["opc-retry-token"] = str(uuid.uuid4())

    return headers