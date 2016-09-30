<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Claim;
use Lcobucci\JWT\Validation\Constraint;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
final class GreaterOrEqualsTo extends BaseConstraint
{
    /**
     * {@inheritdoc}
     */
    public function isValid(Claim $claim)
    {
        return $claim->getValue() >= $this->value;
    }

    /**
     * {@inheritdoc}
     */
    public function getMessage(Claim $claim)
    {
        return sprintf(
            'Claim %s expected to be greater or equals to %s, %s given',
            $claim->getName(),
            $this->value,
            $claim->getValue()
        );
    }
}
