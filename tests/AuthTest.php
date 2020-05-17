<?php 

declare(strict_types=1);

use Arifrh\DynaModel\DB;
use PHPUnit\Framework\TestCase;

/**
*  Unit Test for StarterTest Class
*
*  @author Arif RH
*/
final class AuthTest extends TestCase
{
	/**
	 * Auth Object
	 *
	 * @var object $auth
	 */
	protected $auth;

	/**
	 * Email dummy
	 *
	 * @var string $email
	 */
	protected $email = 'arifrahmanhakim.net@gmail.com';

	/**
	 * Email dummy #2
	 *
	 * @var string $email2
	 */
	protected $email2 = 'arif.rh@diginiq.net';

	/**
	 * Email dummy #3 for update
	 *
	 * @var string $newEmail
	 */
	protected $newEmail = 'arman.is.nice@gmail.com';

	/**
	 * Invalid Email dummy
	 *
	 * @var string $invalidEmail
	 */
	protected $invalidEmail = 'invalid-email.com';

	/**
	 * Week Password dummy
	 *
	 * @var string $weakPassword
	 */
	protected $weakPassword = '123456';

	/**
	 * Short Password dummy
	 *
	 * @var string $shortPassword
	 */
	protected $shortPassword = '1234';

	/**
	 * Password dummy
	 *
	 * @var string $password
	 */
	protected $password = 'admin@PRO#123';

	/**
	 * Fullname dummy
	 *
	 * @var string $fullname
	 */
	protected $fullname = 'Arif Rahman Hakim';

	/**
	 * Username dummy
	 *
	 * @var string $username
	 */
	protected $username = 'arif-rh';

	/**
	 * Setup inital action that will be used in all unit test case
	 */
	public function setUp(): void
	{
		$this->auth = new Arifrh\Auth\Auth();
		$this->auth->testMode();
	}

	public function tearDown(): void
	{
		$this->auth = null;
	}

	protected function cleanTestdata()
	{
		$config = $this->auth->config;

		// clean-up all test data
		$user = DB::table($config->userTable);
		$user->truncate();

		$req = DB::table($config->authRequestTable);
		$req->truncate();

		$attempt = DB::table($config->authAttemptTable);
		$attempt->truncate();
	}

	protected function clearAttemptTest()
	{
		$attempt = DB::table($this->auth->config->authAttemptTable);
		$attempt->deleteBy(['ip' => '127.0.0.1']);
	}

	protected function clearTokenRequestTest($token)
	{
		$request = DB::table($this->auth->config->authRequestTable);
		$request->deleteBy(['token' => $token]);
	}

	public function testRegister()
	{
		$this->cleanTestdata();

		// login without activation, account directly activated and can do login
		$return = $this->auth->register($this->email2, $this->password, $this->password, ['fullname' => 'Arif RH'], false);

		$this->assertFalse($return['error']);
		$this->assertSame($return['message'], lang('Auth.register_success_emailmessage_suppressed'));

		$userData = [
			'fullname' => $this->fullname,
			'username' => $this->username,
			'group_id' => 1,
			'role_id'  => 1
		];

		// register account with email activation
		$return = $this->auth->register($this->email, $this->password, $this->password, $userData);

		$this->assertFalse($return['error']);
		$this->assertSame($return['message'], lang('Auth.register_success'));

		// if previous registration is succeed, this test below will failed
		$return = $this->auth->register($this->email, $this->password, $this->password, $userData, false);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.email_taken', [$this->email]));

		// try multiple invalid registration, to trigger locked out
		for ($i = 0; $i <= $this->auth->config->attemptsBeforeLocked; $i++)
		{
			$return = $this->auth->register($this->email, $this->password, $this->password, $userData, false);	
		}

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.user_blocked'));
	}

	/**
	 * @depends testRegister
	 */
	public function testLogin()
	{
		// clean up previous locked out to do next test
		$this->clearAttemptTest();

		// login with invalid email
		$return = $this->auth->login($this->invalidEmail, $this->password);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang("Auth.email_invalid"));

		// login with weak password
		$return = $this->auth->login($this->email, $this->weakPassword);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang("Auth.password_weak"));

		// login with not existing account
		$return = $this->auth->login($this->email . 'not-exist', $this->password);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang("Auth.account_not_found"));

		// login with incorrect password
		$return = $this->auth->login($this->email, $this->password . 'incorrect');

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang("Auth.email_password_incorrect"));

		// login with correct password for account not activated
		$return = $this->auth->login($this->email, $this->password);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang("Auth.account_inactive"));

		// this is the 6th try, so it should be locked out
		$return = $this->auth->login($this->email, $this->password);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang("Auth.user_blocked"));
		$this->assertFalse($this->auth->checkSession($this->auth->getCurrentSessionHash()));

		/**
		 * IP was locked out, so need clear it to proceed next test
		 */
		$this->clearAttemptTest();

		// login with correct password for active account
		$return = $this->auth->login($this->email2, $this->password);

		$this->assertFalse($return['error']);

		$newAuth = new \Arifrh\Auth\Auth(new \Arifrh\AuthTests\Config\Auth); 
		$newAuth->testMode();

		// login with correct password for active account, with rehash password
		$return = $newAuth->login($this->email2, $this->password);

		$this->assertFalse($return['error']);
		$this->assertTrue($newAuth->isLogged());
		$this->assertSame($return['message'], lang("Auth.logged_in"));
		$this->assertSame($return['hash'], get_cookie($this->auth->config->cookieName));

		$user = $this->auth->getCurrentUser();

		$this->assertSame($this->email2, $user['email']);
	}

	public function testActivateAccount()
	{
		$uid    = $this->auth->getUID($this->email);
		$token  = $this->auth->getUserRequestToken($uid, 'activation');

		// test invalid token length
		$return = $this->auth->activateUserAccount(substr($token, 0, 5));

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.activationkey_invalid'));

		// test incorrect token value
		$return = $this->auth->activateUserAccount('1234567890ABCDEFGHIJ');

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.activationkey_incorrect'));

		// try multiple invalid registration, to trigger locked out
		for ($i = 0; $i <= $this->auth->config->attemptsBeforeLocked; $i++)
		{
			$return = $this->auth->activateUserAccount('1234567890ABCDEFGHI' . $i);
		}

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.user_blocked'));

		// resend activation when user was locked out
		$return = $this->auth->resendActivation($this->email);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.user_blocked'));

		// delete block to enable next test case
		$this->clearAttemptTest();

		// test resend activation with invalid email
		$return = $this->auth->resendActivation($this->invalidEmail);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.email_invalid'));

		// test resend activation with unregistered email
		$return = $this->auth->resendActivation('unegistered-email' . $this->email);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.email_incorrect'));

		// resend activation when currently have it
		$return = $this->auth->resendActivation($this->email);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.activation_exists'));

		// clear existing token for testing purpose
		$this->clearTokenRequestTest($token);

		$return = $this->auth->resendActivation($this->email);

		$this->assertFalse($return['error']);
		$this->assertSame($return['message'], lang('Auth.activation_sent'));

		// get new token
		$token = $this->auth->getUserRequestToken($uid, 'activation');

		$return = $this->auth->activateUserAccount($token);

		$this->assertFalse($return['error']);
		$this->assertSame($return['message'], lang('Auth.account_activated'));	

		// test when activation already completed
		$return = $this->auth->resendActivation($this->email);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.already_activated'));
	}

	public function testLogout()
	{
		$hash = $this->auth->getCurrentSessionHash();

		$this->assertTrue($this->auth->checkSession($hash));

		$this->auth->logout($hash);

		// this should be false after logout
		$this->assertFalse($this->auth->checkSession($hash));
		$this->assertFalse($this->auth->isLogged());

		// login another activated account to test logout by uid
		$return = $this->auth->login($this->email, $this->password);

		$this->assertFalse($return['error']);
		$this->assertSame($return['message'], lang("Auth.logged_in"));
		$this->assertSame($return['hash'], $this->auth->getCurrentSessionHash());

		$uid = $this->auth->getCurrentUID();

		$this->auth->logoutAll($uid);

		$this->assertFalse($this->auth->isLogged());
	}

	public function testValidateEmail()
	{
		// minimal enail length is 8
		$return = $this->auth->register('a@b.com', $this->password, $this->password);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.email_short', [$this->auth->config->verifyEmailMinLength]));

		// maximal email length is 50
		$return = $this->auth->register('a123456789b123456789c123456789d123456789@e123456789.com', $this->password, $this->password);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.email_long', [$this->auth->config->verifyEmailMaxLength]));

		// register with invalid email
		$return = $this->auth->register($this->invalidEmail, $this->password, $this->password);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.email_invalid'));
	}

	public function testValidatePassword()
	{
		// using not matching password confirmation
		$return = $this->auth->register($this->email, $this->password, $this->password . $this->shortPassword);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang("Auth.password_nomatch"));

		// using short password
		$return = $this->auth->register($this->email, $this->shortPassword, $this->shortPassword);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.password_short'));

		// using weak password
		$return = $this->auth->register($this->email, $this->weakPassword, $this->weakPassword);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.password_weak'));
	}

	public function testChangeEmail()
	{
		$uid = $this->auth->getUID($this->email);

		$return = $this->auth->changeEmail($uid, $this->email, $this->password);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.email_taken', [$this->email]));

		// test with incorrect password
		$return = $this->auth->changeEmail($uid, $this->newEmail, $this->password . 'wrong');

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.password_incorrect'));

		$return = $this->auth->changeEmail($uid, $this->newEmail, $this->password . 'wrong');

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.user_blocked'));

		// clean blocked status to continue testing
		$this->clearAttemptTest();

		// test change with invalid email
		$return = $this->auth->changeEmail($uid, 'a@b.com', $this->password);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.email_short', [$this->auth->config->verifyEmailMinLength]));

		$return = $this->auth->changeEmail($uid, $this->newEmail, $this->password);

		$this->assertFalse($return['error']);
		$this->assertSame($return['message'], lang('Auth.email_changed'));

		$user = $this->auth->getUser($uid);

		$this->assertSame($this->newEmail, $user['email']);
	}

	public function testChangePassword()
	{
		$uid = $this->auth->getUID($this->newEmail);

		$newPassword = 'user@PRO#123';

		// change with incorrect current password
		$return = $this->auth->changePassword($uid, 'wrong@Pass#123', $newPassword, $newPassword);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.password_incorrect'));

		// change with weak current password
		$return = $this->auth->changePassword($uid, $this->weakPassword, $newPassword, $newPassword);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.password_weak'));

		// change using weak password
		$return = $this->auth->changePassword($uid, $this->password, $this->weakPassword, $this->weakPassword);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.password_weak'));

		// change using unmatch confirm new password
		$return = $this->auth->changePassword($uid, $this->password, $newPassword, $this->weakPassword);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.newpassword_nomatch'));

		// change using invalid $uid
		$return = $this->auth->changePassword(99, $this->password, $newPassword, $newPassword);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.account_not_found'));

		// on purpose: repeat test to trigger locked out
		$this->auth->changePassword(88, $this->password, $newPassword, $newPassword);
		$return = $this->auth->changePassword(77, $this->password, $newPassword, $newPassword);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.user_blocked'));

		// clean locked out, so next test should be fine
		$this->clearAttemptTest();

		$return = $this->auth->changePassword($uid, $this->password, $newPassword, $newPassword);

		$this->assertFalse($return['error']);
		$this->assertSame($return['message'], lang('Auth.password_changed'));

		// logout and test login with new password
		$this->auth->logout($this->auth->getCurrentSessionHash());

		$this->auth->login($this->newEmail, $newPassword);

		$this->assertTrue($this->auth->isLogged());
	}

	public function testUserManagement()
	{
		$this->auth->logout($this->auth->getCurrentSessionHash());

		$this->assertFalse($this->auth->isLogged());

		$this->auth->login($this->email2, $this->password);

		$this->assertTrue($this->auth->isLogged());

		$uid   = $this->auth->getCurrentUID();
		$group = ['Admin', 'User'];
		$role  = ['Web Admin', 'User'];

		$this->assertFalse($this->auth->hasRoles($role));
		$this->assertFalse($this->auth->hasRoles([3]));
		$this->assertFalse($this->auth->inGroups($group));
		$this->assertFalse($this->auth->inGroups([2]));

		$this->auth->updateUser($uid, ['role_id' => 3, 'group_id' => 2]);

		$this->assertTrue($this->auth->hasRoles($role));
		$this->assertTrue($this->auth->hasRoles([3]));
		$this->assertTrue($this->auth->inGroups($group));
		$this->assertTrue($this->auth->inGroups([2]));
	}

	public function testResetPassword()
	{
		// this should return error, because email has been changed
		$return = $this->auth->requestReset($this->email);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang("Auth.email_incorrect"));

		$return = $this->auth->requestReset($this->newEmail);

		$this->assertFalse($return['error']);
		$this->assertSame($return['message'], lang("Auth.reset_requested"));

		$uid   = $this->auth->getUID($this->newEmail);
		$token = $this->auth->getUserRequestToken($uid, 'reset');

		// test invalid token length
		$return = $this->auth->resetPass(substr($token, 0, 5), $this->password, $this->password);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.resetkey_invalid'));

		// test incorrect token value
		$return = $this->auth->resetPass('1234567890ABCDEFGHIJ', $this->password, $this->password);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.resetkey_incorrect'));

		// test reset with weak password
		$return = $this->auth->resetPass($token, $this->weakPassword, $this->weakPassword);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.password_weak'));

		// test reset with unmacth password
		$return = $this->auth->resetPass($token, $this->password, $this->weakPassword);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.newpassword_nomatch'));

		$currentPassword = 'user@PRO#123';

		// test reset with existing password
		$return = $this->auth->resetPass($token, $currentPassword, $currentPassword);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.newpassword_match'));

		// test reset with existing password
		$return = $this->auth->resetPass($token, $this->password, $this->password);

		$this->assertFalse($return['error']);
		$this->assertSame($return['message'], lang('Auth.password_reset'));

		$this->auth->login($this->newEmail, $this->password);

		$this->assertTrue($this->auth->isLogged());
	}

	public function testDeleteAccount()
	{
		$uid   = $this->auth->getUID($this->newEmail);

		$return = $this->auth->secureDeleteAccount($uid, $this->weakPassword);

		$this->assertTrue($return['error']);
		$this->assertSame($return['message'], lang('Auth.password_incorrect'));

		$return = $this->auth->secureDeleteAccount($uid, $this->password);

		$this->assertFalse($return['error']);
		$this->assertSame($return['message'], lang('Auth.account_deleted'));
	}
}
