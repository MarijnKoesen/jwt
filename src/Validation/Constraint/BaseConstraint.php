<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Claim;
use Lcobucci\JWT\ConstraintViolationException;
use Lcobucci\JWT\Validation\Constraint;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
abstract class BaseConstraint implements Constraint
{
    /**
     * @var mixed
     */
    protected $value;

    /**
     * @param mixed $value
     */
    public function __construct($value)
    {
        $this->value = $value;
    }

    /**
     * {@inheritdoc}
     */
    public function validate(Claim $claim)
    {
        if ($this->isValid($claim)) {
            return;
        }

        throw new ConstraintViolationException($this->getMessage($claim));
    }

    public abstract function isValid(Claim $claim): bool;
    public abstract function getMessage(Claim $claim): string;
}