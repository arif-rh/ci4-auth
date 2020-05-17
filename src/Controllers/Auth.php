<?php

namespace Arifrh\Auth\Controllers;

/**
 * This Class provide method for Forbidden page
 */
class Auth extends \CodeIgniter\Controller
{
	/**
	 * Display 403 - Forbidden page when current user role is denied
	 */
	public function deniedRole()
	{
		echo view('\Arifrh\Auth\Views\Forbidden', ['message' => lang('Auth.invalid_role')]);
	}

	/**
	 * Display 403 - Forbidden page when current user group is denied
	 */
	public function deniedGroup()
	{
		echo view('\Arifrh\Auth\Views\Forbidden', ['message' => lang('Auth.invalid_group')]);
	}
}