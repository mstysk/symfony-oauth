<?php

declare(strict_types=1);

namespace App\Security;

enum InvalidJwtReason: string
{
    case Malformed = 'malformed';
    case SignatureMismatch = 'signature_mismatch';
    case Expired = 'expired';
    case IssuerMismatch = 'issuer_mismatch';
    case AudienceMismatch = 'audience_mismatch';
    case KidMismatch = 'kid_mismatch';
    case Revoked = 'revoked';
}
