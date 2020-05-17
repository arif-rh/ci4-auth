<?php

return [
	'user_blocked'       => 'You are currently locked out of the system.',
	'user_verify_failed' => 'Captcha Code was invalid.',

	'account_email_invalid'    => 'Email address is incorrect or banned',
	'account_password_invalid' => 'Password is invalid',
	'account_not_found'        => 'Account not found.',
	'account_inactive'         => 'Account has not yet been activated.',
	'account_activated'        => 'Account activated.',

	'login_remember_me_invalid' => 'The remember me field is invalid.',

	'email_password_invalid'   => 'Email address / password are invalid.',
	'email_password_incorrect' => 'Password are incorrect for given EMail.',

	'remember_me_invalid' => 'The remember me field is invalid.',

	'password_short'     => 'Password is too short.',
	'password_weak'      => 'Password is too weak.',
	'password_nomatch'   => 'Passwords do not match.',
	'password_changed'   => 'Password changed successfully.',
	'password_incorrect' => 'Current password is incorrect.',
	'password_notvalid'  => 'Password is invalid.',

	'newpassword_short'   => 'New password is too short.',
	'newpassword_long'    => 'New password is too long.',
	'newpassword_invalid' => 'New password must contain at least one uppercase and lowercase character, and at least one digit.',
	'newpassword_nomatch' => 'New passwords do not match.',
	'newpassword_match'   => 'New password is the same as the old password.',

	'email_short'     => 'Email address is too short. It need at least {0, number} characters.',
	'email_long'      => 'Email address is too long. It can not be exceed from {0, number} characters.',
	'email_invalid'   => 'It is not a correct Email address.',
	'email_incorrect' => 'Email address is incorrect.',
	'email_banned'    => 'This email address is not allowed.',
	'email_changed'   => 'Email address changed successfully.',
	'email_taken'     => 'The email address ({0}) is already in use.',

	'newemail_match' => 'New email matches previous email.',

	'logged_in'  => 'You are now logged in.',
	'logged_out' => 'You are now logged out.',

	'system_error' => 'A system error has been encountered. Please try again.',

	'register_success'                         => 'Account created. Activation email sent to email.',
	'register_success_emailmessage_suppressed' => 'Account created.',

	'resetkey_invalid'   => 'Reset key is invalid.',
	'resetkey_incorrect' => 'Reset key is incorrect.',
	'resetkey_expired'   => 'Reset key has expired.',
	'password_reset'     => 'Password reset successfully.',

	'activationkey_invalid'   => 'Activation key is invalid.',
	'activationkey_incorrect' => 'Activation key is incorrect.',
	'activationkey_expired'   => 'Activation key has expired.',

	'reset_requested'                         => 'Password reset request sent to email address.',
	'reset_requested_emailmessage_suppressed' => 'Password reset request is created.',
	'reset_exists'                            => 'A reset request already exists.',

	'already_activated' => 'Account is already activated.',
	'activation_sent'   => 'Activation email has been sent.',
	'activation_exists' => 'An activation email has already been sent.',

	'email_activation_subject' => '{0} - Activate account',
	'email_activation_body'    => "Hello,<br/><br/> To be able to log in to your account you first need to activate your account by clicking on the following link : <strong><a href={0}{1}/{2}'>{0}{1}/{2}</a></strong><br/><br/> You then need to use the following activation key: <strong>{2}</strong><br/><br/> If you did not sign up on {0} recently then this message was sent in error, please ignore it.",
	'email_activation_altbody' => 'Hello, ' . '\n\n' . 'To be able to log in to your account you first need to activate your account by visiting the following link :' . '\n{0}{1}/{2}\n\n' . 'You then need to use the following activation key: {2}' . '\n\n' . 'If you did not sign up on {0} recently then this message was sent in error, please ignore it.',

	'email_reset_subject' => '{0} - Password reset request',
	'email_reset_body'    => "Hello,<br/><br/>To reset your password click the following link :<br/><br/><strong><a href={0}{1}/{2}'>{0}{1}/{2}</a></strong><br/><br/>You then need to use the following password reset key: <strong>{2}</strong><br/><br/>If you did not request a password reset key on {0} recently then this message was sent in error, please ignore it.",
	'email_reset_altbody' => 'Hello, ' . '\n\n' . 'To reset your password please visiting the following link :' . '\n{0}{1}/{2}\n\n' . 'You then need to use the following password reset key: {2}' . '\n\n' . 'If you did not request a password reset key on {0} recently then this message was sent in error, please ignore it.',

	'account_deleted'   => 'Account deleted successfully.',
	'function_disabled' => 'This function has been disabled.',

	'unknown_mail_type' => 'Unknown email type. Email not sent!',
	'activation_email_not_sent' => 'Email Activation failed to be sent.',
	'reset_email_not_sent' => 'Email for Reset Password failed to be sent.',

	'invalid_role'  => 'You do not have the valid role to access this page.',
	'invalid_group' => 'You do not belong to the proper group to access this page.',
];
