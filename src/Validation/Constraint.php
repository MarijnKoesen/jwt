<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Validation;

use Lcobucci\JWT\Claim;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 *
 * @since 4.0.0
 */
interface Constraint
{
    /**
     * @param Claim $claim
     *
     * @throws ConstraintViolationException
     */
    public function validate(Claim $claim);
}
