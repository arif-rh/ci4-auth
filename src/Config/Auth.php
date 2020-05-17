<?php

namespace Arifrh\Auth\Config;

/**
 * PHPAuth Config class
 */

class Auth extends \CodeIgniter\Config\BaseConfig
{
	/**
	 * Config Table name
	 *
	 * @var string $configTable
	 */
	public $configTable = 'settings';

	/**
	 * Login Attempt Table name
	 *
	 * @var string $userTable
	 */
	public $authAttemptTable = 'auth_attempts';

	/**
	 * Auth Request Table name
	 *
	 * @var string $authRequestTable
	 */
	public $authRequestTable = 'auth_requests';

	/**
	 * Auth Session Table name
	 *
	 * @var string $authSessionTable
	 */
	public $authSessionTable = 'auth_sessions';

	/**
	 * User Table name
	 *
	 * @var string $userTable
	 */
	public $userTable = 'users';

	/**
	 * User Role Table name
	 *
	 * @var string $userRoleTable
	 */
	public $userRoleTable = 'user_roles';

	/**
	 * User Group Table name
	 *
	 * @var string $userGroupTable
	 */
	public $userGroupTable = 'user_groups';

	/**
	 * Site Language
	 *
	 * @var string $siteLang
	 */
	public $siteLang = 'en';

	/**
	 * Use validation for password strengh?
	 *
	 * @var boolean $validatePasswordStrength
	 */
	public $validatePasswordStrength = true;

	/**
	 * If use validatePasswordStrength, then set passwordMinScore
	 *
	 * @var int $passwordMinScore
	 */
	public $passwordMinScore = 3;

	/**
	 * Minimal Password length
	 *
	 * @var int $passwordMinLength
	 */
	public $passwordMinLength = 5;

	/**
	 * Cost used in Bcript
	 *
	 * @var int $bcryptCost
	 */
	public $bcryptCost = 10;
}