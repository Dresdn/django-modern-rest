import datetime as dt
from typing import TYPE_CHECKING, Literal, Self, overload

from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpRequest
from typing_extensions import override

from dmr.exceptions import NotAuthenticatedError
from dmr.openapi.objects import Reference, SecurityRequirement, SecurityScheme
from dmr.security.base import AsyncAuth, SyncAuth

if TYPE_CHECKING:
    from django.contrib.auth.base_user import AbstractBaseUser

    from dmr.controller import Controller
    from dmr.endpoint import Endpoint
    from dmr.security.token.models import Token
    from dmr.serializer import BaseSerializer


def _token_model() -> 'type[Token]':
    """Deferred import so models are not loaded before app registry is ready."""
    from dmr.security.token.models import Token  # noqa: PLC0415

    return Token


class _TokenValidationMixin:
    """Mixin providing token lookup, user checks, and usage tracking."""

    __slots__ = ()

    def _check_token(self, raw_token: str) -> 'Token':
        """Raise NotAuthenticatedError if token is invalid, else return it."""
        model = _token_model()
        token_hash = model.objects.hash_token(raw_token)
        try:
            token = model.objects.select_related('user').get(
                token_hash=token_hash,
            )
        except ObjectDoesNotExist:
            raise NotAuthenticatedError from None
        if not token.is_active:
            raise NotAuthenticatedError
        return token

    async def _acheck_token(self, raw_token: str) -> 'Token':
        """Async version of _check_token."""
        model = _token_model()
        token_hash = model.objects.hash_token(raw_token)
        try:
            token = await model.objects.select_related('user').aget(
                token_hash=token_hash,
            )
        except ObjectDoesNotExist:
            raise NotAuthenticatedError from None
        if not token.is_active:
            raise NotAuthenticatedError
        return token

    def _check_user(self, user: 'AbstractBaseUser') -> None:
        """Raise NotAuthenticatedError if user account is not active."""
        if not user.is_active:
            raise NotAuthenticatedError

    def _mark_token_used(self, token: 'Token') -> None:
        """Persist token usage timestamp after successful authentication."""
        token.last_used_at = dt.datetime.now(dt.UTC)
        token.save(update_fields=['last_used_at', 'updated_at'])

    async def _amark_token_used(self, token: 'Token') -> None:
        """Async version of :meth:`_mark_token_used`."""
        token.last_used_at = dt.datetime.now(dt.UTC)
        await token.asave(update_fields=['last_used_at', 'updated_at'])


class _BaseTokenAuth(_TokenValidationMixin):
    """Base class for DB-backed opaque token authentication."""

    __slots__ = (
        'cookie_name',
        'header_name',
        'prefix',
        'query_param',
        'security_scheme_name',
    )

    def __init__(
        self,
        *,
        header_name: str = 'X-API-Token',
        prefix: str = '',
        query_param: str = 'token',
        cookie_name: str = 'token',
        security_scheme_name: str = 'token',
    ) -> None:
        """
        Apply possible customizations.

        - *header_name* — which header carries the raw token (default
          ``X-API-Token``).  Use ``'Authorization'`` for RFC 7235-style
          bearer auth (see *prefix* below).
        - *prefix* — scheme prefix expected before the token in the header
          value (default ``''``, i.e. the header value is used verbatim).
          Set to ``'Token'`` or ``'Bearer'`` when *header_name* is
          ``'Authorization'`` — e.g. ``prefix='Token'`` requires the client
          to send ``Authorization: Token <raw-token>``.
        - *query_param* — which query string parameter carries the raw token
          (default ``token``).
        - *cookie_name* — which cookie carries the raw token (default
          ``token``).
        - *security_scheme_name* — name used in OpenAPI security scheme map.

        **Common configurations:**

        .. code-block:: python

            # Default — custom header, no prefix
            TokenSyncAuth()  # X-API-Token: <token>

            # DRF-compatible
            TokenSyncAuth(header_name='Authorization', prefix='Token')

            # Bearer style
            TokenSyncAuth(header_name='Authorization', prefix='Bearer')
        """
        self.header_name = header_name
        self.prefix = prefix
        self.query_param = query_param
        self.cookie_name = cookie_name
        self.security_scheme_name = security_scheme_name

    @property
    def security_schemes(self) -> dict[str, SecurityScheme | Reference]:
        """Provides a security schema definition."""
        if self.header_name == 'Authorization':
            # RFC 7235 reserves the Authorization header for the `http` scheme.
            # Using `apiKey` + `name: Authorization` is invalid in OpenAPI 3.x.
            return {
                self.security_scheme_name: SecurityScheme(
                    type='http',
                    scheme='bearer',
                    description='Opaque token authentication',
                ),
            }
        return {
            self.security_scheme_name: SecurityScheme(
                type='apiKey',
                name=self.header_name,
                security_scheme_in='header',
                description='Opaque token authentication',
            ),
        }

    @property
    def security_requirement(self) -> SecurityRequirement:
        """Provides a security schema usage requirement."""
        return {self.security_scheme_name: []}

    def _raw_token_from_request(self, request: HttpRequest) -> str | None:
        """Extract the raw token string from the request."""
        raise NotImplementedError


class _HeaderTokenMixin(_BaseTokenAuth):
    """Read the raw token from a request header."""

    __slots__ = ()

    @override
    def _raw_token_from_request(self, request: HttpRequest) -> str | None:
        header_value = request.headers.get(self.header_name)
        if header_value is None:
            return None
        if self.prefix:
            expected = f'{self.prefix} '
            if not header_value.startswith(expected):
                return None
            return header_value[len(expected) :]
        return header_value


class _QueryTokenMixin(_BaseTokenAuth):
    """
    Read the raw token from a query string parameter.

    .. warning::
        Tokens in query strings appear in server access logs, browser history,
        and HTTP ``Referer`` headers.  Prefer header-based auth for any
        context where security is a concern.
    """

    __slots__ = ()

    @override
    def _raw_token_from_request(self, request: HttpRequest) -> str | None:
        return request.GET.get(self.query_param)

    @property
    @override
    def security_schemes(self) -> dict[str, SecurityScheme | Reference]:
        return {
            self.security_scheme_name: SecurityScheme(
                type='apiKey',
                name=self.query_param,
                security_scheme_in='query',
                description='Opaque token authentication via query string',
            ),
        }


class _CookieTokenMixin(_BaseTokenAuth):
    """
    Read the raw token from a cookie.

    .. warning::
        Cookie-based authentication is vulnerable to CSRF attacks in
        browser-facing contexts.  Ensure that
        ``django.middleware.csrf.CsrfViewMiddleware`` is active whenever
        this auth class is used in a browser-facing application.
    """

    __slots__ = ()

    @override
    def _raw_token_from_request(self, request: HttpRequest) -> str | None:
        return request.COOKIES.get(self.cookie_name)

    @property
    @override
    def security_schemes(self) -> dict[str, SecurityScheme | Reference]:
        return {
            self.security_scheme_name: SecurityScheme(
                type='apiKey',
                name=self.cookie_name,
                security_scheme_in='cookie',
                description='Opaque token authentication via cookie',
            ),
        }


class TokenSyncAuth(_HeaderTokenMixin, SyncAuth):
    """Sync opaque token auth; reads from ``X-API-Token`` by default."""

    __slots__ = ()

    @override
    def __call__(
        self,
        endpoint: 'Endpoint',
        controller: 'Controller[BaseSerializer]',
    ) -> Self | None:
        """Authenticate via opaque token in request header."""
        raw_token = self._raw_token_from_request(controller.request)
        if raw_token is None:
            return None
        token = self._check_token(raw_token)
        self._check_user(token.user)
        self._mark_token_used(token)
        _set_request_attrs(controller.request, token.user, token=token)
        return self


class TokenAsyncAuth(_HeaderTokenMixin, AsyncAuth):
    """Async opaque token auth; reads from ``X-API-Token`` by default."""

    __slots__ = ()

    @override
    async def __call__(
        self,
        endpoint: 'Endpoint',
        controller: 'Controller[BaseSerializer]',
    ) -> Self | None:
        """Authenticate via opaque token in request header."""
        raw_token = self._raw_token_from_request(controller.request)
        if raw_token is None:
            return None
        token = await self._acheck_token(raw_token)
        self._check_user(token.user)
        await self._amark_token_used(token)
        _set_request_attrs(controller.request, token.user, token=token)
        return self


class QueryTokenSyncAuth(_QueryTokenMixin, TokenSyncAuth):
    """
    Sync opaque token auth reading from a query string parameter.

    .. warning::
        Tokens in query strings appear in server access logs, browser history,
        and HTTP ``Referer`` headers.  Prefer :class:`TokenSyncAuth` for any
        context where security is a concern.
    """

    __slots__ = ()


class QueryTokenAsyncAuth(_QueryTokenMixin, TokenAsyncAuth):
    """
    Async opaque token auth reading from a query string parameter.

    .. warning::
        Tokens in query strings appear in server access logs, browser history,
        and HTTP ``Referer`` headers.  Prefer :class:`TokenAsyncAuth` for any
        context where security is a concern.
    """

    __slots__ = ()


class CookieTokenSyncAuth(_CookieTokenMixin, TokenSyncAuth):
    """
    Sync opaque token auth reading from a cookie.

    .. warning::
        Cookie-based authentication is vulnerable to CSRF attacks in
        browser-facing contexts.  Ensure that
        ``django.middleware.csrf.CsrfViewMiddleware`` is active whenever
        this auth class is used in a browser-facing application.
    """

    __slots__ = ()


class CookieTokenAsyncAuth(_CookieTokenMixin, TokenAsyncAuth):
    """
    Async opaque token auth reading from a cookie.

    .. warning::
        Cookie-based authentication is vulnerable to CSRF attacks in
        browser-facing contexts.  Ensure that
        ``django.middleware.csrf.CsrfViewMiddleware`` is active whenever
        this auth class is used in a browser-facing application.
    """

    __slots__ = ()


@overload
def request_token(
    request: HttpRequest,
    *,
    strict: Literal[True],
) -> 'Token': ...


@overload
def request_token(
    request: HttpRequest,
    *,
    strict: bool = False,
) -> 'Token | None': ...


def request_token(
    request: HttpRequest,
    *,
    strict: bool = False,
) -> 'Token | None':
    """
    Return the Token from request, if it was authed with one.

    When *strict* is passed and *request* has no token,
    we raise :exc:`AttributeError`.
    """
    token = getattr(request, '__dmr_token__', None)
    if token is None and strict:
        raise AttributeError('__dmr_token__')
    return token


def _set_request_attrs(
    request: HttpRequest,
    user: 'AbstractBaseUser',
    *,
    token: 'Token',
) -> None:
    """Set all required properties to the authed request."""
    request.user = user

    async def auser() -> 'AbstractBaseUser':  # noqa: WPS430
        return user

    request.auser = auser
    request.__dmr_token__ = token  # type: ignore[attr-defined]
