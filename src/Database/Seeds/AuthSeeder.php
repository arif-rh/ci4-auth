<?php

namespace Arifrh\Auth\Database\Seeds;

class AuthSeeder extends \CodeIgniter\Database\Seeder
{
	/**
	 * Run Database Seeder
	 *
	 * @return void
	 */
	public function run()
	{
		$config = \CodeIgniter\Config\Factories::config('Auth');

		$sql = "
		INSERT INTO " . $this->db->prefixTable($config->configTable) . " (`name`, `value`) VALUES
			('site_name', 'App Starter Pro'),
			('site_email',  'mail@diginiq.net'),
			('site_key',  'fghuior.)/!/jdUkd8s2!7HVHG7777ghg'),
			('site_activation_page',  'activate'),
			('site_password_reset_page',  'reset'),
			('site_timezone', 'Asia/Tokyo'),
			('site_language', 'en_GB'),
			('attack_mitigation_time',  '+30 minutes'),
			('attempts_before_locked',  '5'),
			('cookie_forget', '+30 minutes'),
			('cookie_name', 'auth_sess_cookie'),
			('cookie_remember', '+1 month'),
			('cookie_renew', '+5 minutes'),
			('allow_concurrent_sessions', FALSE),
			('emailmessage_suppress_activation',  '0'),
			('emailmessage_suppress_reset', '0'),
			('mail_charset','UTF-8'),
			('table_emails_banned', 'phpauth_emails_banned'),
			('table_translations', 'phpauth_translation_dictionary'),
			('verify_email_max_length', '50'),
			('verify_email_min_length', '8'),
			('verify_email_use_banlist',  '1'),
			('verify_password_min_length',  '3'),
			('request_key_expiration', '+10 minutes'),
			('recaptcha_enabled', 0),
			('recaptcha_site_key', ''),
			('recaptcha_secret_key', '');
		";

		$this->db->query($sql);

		$this->db->query("INSERT INTO " . $this->db->prefixTable($config->userGroupTable) . " (`group`, `description`) VALUES ('Super Admin', 'Super Admin'), ('Admin', 'Admin'), ('User', 'User');");

		$this->db->query("INSERT INTO " . $this->db->prefixTable($config->userRoleTable) . " (`group_id`, `role`, `description`) VALUES (1, 'Administrator', 'Administrator'), (2, 'Web Admin', 'Web Admin'), (3, 'User', 'User');");
	}
}