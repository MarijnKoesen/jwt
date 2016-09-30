<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Validation;

use Lcobucci\JWT\Token;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 *
 * @since 4.0.0
 */
final class Validator implements \Lcobucci\JWT\Validator
{
    public function validate(Token $token, array $constraints): Result
    {
        $violations = [];
        $claims = $token->getClaims();

        foreach ($constraints as $claim => $constraint) {
            if (!array_key_exists($claim, $claims)) {
                continue;
            }

            try {
                $constraint->validate($claims[$claim]);
            } catch (ConstraintViolationException $e) {
                $violations[] = $e;
            }
        }

        return new Result($violations);
    }
}
