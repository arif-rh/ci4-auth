<?php

namespace Arifrh\Auth\Database\Seeds;

class UserSeeder extends \CodeIgniter\Database\Seeder
{
	/**
	 * Run Database Seeder
	 *
	 * @return void
	 */
	public function run()
	{
		$config = \CodeIgniter\Config\Config::get('Auth');

		$userPassword = 'arif@RH&888';

		$password = password_hash($userPassword, PASSWORD_BCRYPT, ['cost' => $config->bcryptCost]);
		$sql = "
		INSERT INTO " . $config->userTable . " (`email`, `password`, `group_id`, `role_id`, `active`) VALUES
			('arifrahmanhakim.net@gmail.com', '" . $password . "', 1, 1, 1);
		";

		$this->db->query($sql);
	}
}