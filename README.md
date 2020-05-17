# PHPAuth for CodeIgniter 4

This package is adopted from [PHPAuth](https://github.com/PHPAuth/PHPAuth), but completedly rewrited for easy implementation with CodeIgniter 4.

## Installation

1. `composer require arif-rh/ci4-auth`
2. make sure you have set you database config properly
3. `php spark migrate -n Arifrh\Auth`
4. `php spark db:seed \\Arifrh\\Auth\\Database\\Seeds\\AuthSeeder`

## Features

- Register
- Activation email
- Login
- Request reset password
- Encrypt password using bcrypt
- Prevent brute force attack by limiting request

## Acknowledgments

- [PHPAuth](https://github.com/PHPAuth/PHPAuth)