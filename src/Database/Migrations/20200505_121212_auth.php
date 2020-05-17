<?php

namespace Arifrh\Auth\Database\Migrations;

use \CodeIgniter\Config\BaseConfig;

class AuthMigration extends \CodeIgniter\Database\Migration
{
	/**
	 * Table attributes
	 *
	 * @var mixed $attributes
	 */
	protected $attributes = ['ENGINE' => 'InnoDB'];

	/**
	 * Create Table if Not Exists ?
	 *
	 * @var boolean $ifNotExists
	 */
	protected $ifNotExists = true;

	/**
	 * Run Migragtion
	 *
	 * @return void
	 */
	public function up()
	{
		$config = \CodeIgniter\Config\Config::get('Auth');

		// Config Table
		$this->forge->addField([
			'id'    => [
				'type'           => 'SMALLINT',
				'constraint'     => 6,
				'unsigned'       => true,
				'auto_increment' => true,
			],
			'name'  => [
				'type'       => 'VARCHAR',
				'constraint' => '100',
			],
			'value' => [
				'type'       => 'VARCHAR',
				'constraint' => '200',
			],
		]);

		$this->forge->addKey('id', true);
		$this->forge->addKey('name');

		$this->forge->createTable($config->configTable, $this->ifNotExists, $this->attributes);

		$this->createAuthAttempts($config);
		$this->createAuthRequests($config);
		$this->createAuthSessions($config);

		// User Groups
		$this->forge->addField([
			'id'     => [
				'type'           => 'SMALLINT',
				'constraint'     => 3,
				'unsigned'       => true,
				'auto_increment' => true,
			],
			'group'  => [
				'type'       => 'VARCHAR',
				'constraint' => '100',
			],
			'active' => [
				'type'       => 'TINYINT',
				'constraint' => 1,
				'default'    => 1,
			],
		]);

		$this->forge->addKey('id', true);
		$this->forge->addKey('group');

		$this->forge->createTable($config->userGroupTable, $this->ifNotExists, $this->attributes);

		// User Roles
		$this->forge->addField([
			'id'       => [
				'type'           => 'SMALLINT',
				'constraint'     => 3,
				'unsigned'       => true,
				'auto_increment' => true,
			],
			'group_id' => [
				'type'       => 'SMALLINT',
				'constraint' => 3,
			],
			'role'     => [
				'type'       => 'VARCHAR',
				'constraint' => '100',
			],
			'active'   => [
				'type'       => 'TINYINT',
				'constraint' => 1,
				'default'    => 1,
			],
		]);

		$this->forge->addKey('id', true);
		$this->forge->addKey('role');

		$this->forge->createTable($config->userRoleTable, $this->ifNotExists, $this->attributes);

		// Users
		$this->forge->addField([
			'id'         => [
				'type'           => 'INT',
				'constraint'     => 11,
				'unsigned'       => true,
				'auto_increment' => true,
			],
			'email'      => [
				'type'       => 'VARCHAR',
				'constraint' => '100',
			],
			'password'   => [
				'type'       => 'VARCHAR',
				'constraint' => '255',
			],
			'fullname'   => [
				'type'       => 'VARCHAR',
				'constraint' => '100',
			],
			'username'   => [
				'type'       => 'VARCHAR',
				'constraint' => '40',
			],
			'group_id'   => [
				'type'       => 'SMALLINT',
				'constraint' => 3,
			],
			'role_id'    => [
				'type'       => 'SMALLINT',
				'constraint' => 3,
			],
			'active'     => [
				'type'       => 'TINYINT',
				'constraint' => 1,
				'default'    => 0,
			],
			'created_at' => [
				'type' => 'DATETIME',
			],
			'updated_at' => [
				'type'  => 'DATETIME',
			],
			'deleted_at' => [
				'type'  => 'DATETIME',
			],
		]);

		$this->forge->addKey('id', true);
		$this->forge->addKey('email', false, true);

		$this->forge->createTable($config->userTable, $this->ifNotExists, $this->attributes);
	}

	/**
	 * Create Login Attempt Table
	 *
	 * @param BaseConfig $config
	 *
	 * @return void
	 */
	protected function createAuthAttempts(BaseConfig $config)
	{
		// Login Attempts
		$this->forge->addField([
			'id'          => [
				'type'           => 'INT',
				'constraint'     => 11,
				'unsigned'       => true,
				'auto_increment' => true,
			],
			'ip'          => [
				'type'       => 'CHAR',
				'constraint' => '39',
			],
			'expire_date' => [
				'type' => 'DATETIME',
			],
			'note'           => [
				'type'       => 'VARCHAR',
				'constraint' => '200',
				'null'       => true,
			],
		]);

		$this->forge->addKey('id', true);
		$this->forge->addKey('ip');

		$this->forge->createTable($config->authAttemptTable, $this->ifNotExists, $this->attributes);
	}

	/**
	 * Create Auth Requests Table
	 *
	 * @param BaseConfig $config
	 *
	 * @return void
	 */
	protected function createAuthRequests(BaseConfig $config)
	{
		// Auth Requests
		$this->forge->addField([
			'id'          => [
				'type'           => 'INT',
				'constraint'     => 11,
				'unsigned'       => true,
				'auto_increment' => true,
			],
			'uid'         => [
				'type'       => 'INT',
				'constraint' => 11,
			],
			'token'       => [
				'type'       => 'CHAR',
				'constraint' => '20',
			],
			'expire_date' => [
				'type' => 'DATETIME',
			],
			'type'        => [
				'type'       => 'ENUM',
				'constraint' => ['activation','reset'],
			],
		]);

		$this->forge->addKey('id', true);
		$this->forge->addKey('type');
		$this->forge->addKey('token');
		$this->forge->addKey('uid');

		$this->forge->createTable($config->authRequestTable, $this->ifNotExists, $this->attributes);
	}

	/**
	 * Create Auth Sessions Table
	 *
	 * @param BaseConfig $config
	 *
	 * @return void
	 */
	protected function createAuthSessions(BaseConfig $config)
	{
		// Auth Sessions
		$this->forge->addField([
			'id'          => [
				'type'           => 'INT',
				'constraint'     => 11,
				'unsigned'       => true,
				'auto_increment' => true,
			],
			'uid'         => [
				'type'       => 'INT',
				'constraint' => 11,
			],
			'hash'        => [
				'type'       => 'CHAR',
				'constraint' => '40',
			],
			'expire_date' => [
				'type' => 'DATETIME',
			],
			'ip'          => [
				'type'       => 'CHAR',
				'constraint' => '39',
			],
			'agent'       => [
				'type'       => 'VARCHAR',
				'constraint' => '200',
			],
			'cookie_crc'  => [
				'type'       => 'VARCHAR',
				'constraint' => '40',
			],
		]);

		$this->forge->addKey('id', true);

		$this->forge->createTable($config->authSessionTable, $this->ifNotExists, $this->attributes);
	}

	/**
	 * Rollback Migration
	 *
	 * @return void
	 */
	public function down()
	{
		$config = \CodeIgniter\Config\Config::get('Auth');

		$this->forge->dropTable($config->configTable);
		$this->forge->dropTable($config->authAttemptTable);
		$this->forge->dropTable($config->authRequestTable);
		$this->forge->dropTable($config->authSessionTable);
		$this->forge->dropTable($config->userGroupTable);
		$this->forge->dropTable($config->userRoleTable);
		$this->forge->dropTable($config->userTable);
	}
}