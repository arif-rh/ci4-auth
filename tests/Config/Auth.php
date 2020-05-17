<?php

namespace Arifrh\AuthTests\Config;

/**
 * PHPAuth Config class
 */

class Auth extends \Arifrh\Auth\Config\Auth
{
	/**
	 * Cost used in Bcript
	 *
	 * @var int $bcryptCost
	 */
	public $bcryptCost = 12;
}