<?php

namespace TackTack\TwoFactor\Service;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;

/**
 * QR code généré côté serveur, en SVG inline (docs/paquet-2fa.md §2 décision #8) :
 * le secret ne part jamais vers un service tiers.
 */
class QrCodeService
{
    public function svg(string $content, int $size = 220): string
    {
        $writer = new Writer(new ImageRenderer(new RendererStyle($size, 2), new SvgImageBackEnd()));
        $svg = $writer->writeString($content);

        // Le prologue XML n'a pas sa place dans du HTML inline.
        return (string) preg_replace('/^<\?xml[^>]*\?>\s*/', '', $svg);
    }
}
