<?php

$routes->group('forbidden', function ($routes)
{
	$routes->add('role', '\Arifrh\Auth\Controllers\Auth::deniedRole', ['as' => 'forbidden-role']);
	$routes->add('group', '\Arifrh\Auth\Controllers\Auth::deniedGroup', ['as' => 'forbidden-group']);
});