<?php namespace Arifrh\Auth;

function is_strong_password($password)
{
	$auth = new \Arifrh\Auth\Auth();

	if (strlen($password) < (int) $auth->config->passwordMinLength )
	{
		return false;
	}

	if ($auth->config->validatePasswordStrength)
	{
		$zxcvbn = new \ZxcvbnPhp\Zxcvbn();

		if ($zxcvbn->passwordStrength($password)['score'] < intval($auth->config->passwordMinScore))
		{
			return false;
		}
	}

	return true;
}

function generate_strong_password($length = 9, $add_dashes = false, $available_sets = 'luds')
{
	$sets = array();

	if (strpos($available_sets, 'l') !== false)
		$sets[] = 'abcdefghjkmnpqrstuvwxyz';

	if (strpos($available_sets, 'u') !== false)
		$sets[] = 'ABCDEFGHJKMNPQRSTUVWXYZ';

	if (strpos($available_sets, 'd') !== false)
		$sets[] = '23456789';

	if (strpos($available_sets, 's') !== false)
		$sets[] = '!@#$%&*?';

	$all = '';
	$password = '';
	foreach ($sets as $set)
	{
		$password .= $set[array_rand(str_split($set))];
		$all .= $set;
	}

	$all = str_split($all);
	for ($i = 0; $i < $length - count($sets); $i++)
		$password .= $all[array_rand($all)];

	$password = str_shuffle($password);

	if (! $add_dashes)
		return $password;

	$dash_len = floor(sqrt($length));
	$dash_str = '';
	while (strlen($password) > $dash_len)
	{
		$dash_str .= substr($password, 0, $dash_len) . '-';
		$password = substr($password, $dash_len);
	}

	$dash_str .= $password;
	return is_strong_password($dash_str) ? $dash_str : generate_strong_password($length, $add_dashes, $available_sets);
}
