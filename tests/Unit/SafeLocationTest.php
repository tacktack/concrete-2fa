<?php

use TackTack\TwoFactor\Http\SafeLocation;

it('accepte les chemins locaux', function (string $uri) {
    expect(SafeLocation::isSafe($uri))->toBeTrue();
})->with(['/', '/dashboard', '/index.php/dashboard/system?x=1', '/a/b#c']);

it('refuse tout ce qui peut sortir du site', function (string $uri) {
    expect(SafeLocation::isSafe($uri))->toBeFalse();
})->with(['', '//evil.example/x', '/\\evil.example/x', '/ok\\x', "/a\r\nSet-Cookie: x", 'http://evil.example/', 'dashboard', "/a\x00b"]);
