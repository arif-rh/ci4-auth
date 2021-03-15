<?php

return [
	'user_blocked'       => 'Akses anda ke sistem terkunci.',
	'user_verify_failed' => 'Kode Captcha tidak benar.',

	'account_email_invalid'    => 'Alamat Email tidak benar atau terlarang.',
	'account_password_invalid' => 'Password tidak benar.',
	'account_not_found'        => 'Akun tidak ditemukan.',
	'account_inactive'         => 'Akun belum diaktifkan.',
	'account_activated'        => 'Akun berhasil diaktifkan.',

	'login_remember_me_invalid' => 'field Ingat saya tidak benar.',

	'email_password_invalid'   => 'Email / password tidak benar.',
	'email_password_incorrect' => 'Password salah.',

	'remember_me_invalid' => 'field Ingat saya tidak benar.',

	'password_short'     => 'Password terlalu pendek.',
	'password_weak'      => 'Password terlalu lemah.',
	'password_nomatch'   => 'Password tidak sesuai.',
	'password_changed'   => 'Password berhasil diubah.',
	'password_incorrect' => 'Password tidak benar.',
	'password_notvalid'  => 'Password tidak benar.',

	'newpassword_short'   => 'Password baru terlalu pendek.',
	'newpassword_long'    => 'Password baru terlalu panjang.',
	'newpassword_invalid' => 'Password baru harus berisi minimal satu huruf kapital, satu huruf kecil, dan satu angka.',
	'newpassword_nomatch' => 'Password baru tidak sesuai.',
	'newpassword_match'   => 'Password baru sama dengan password lama.',

	'email_short'     => 'Email terlalu pendek. Setidaknya butuh {0, number} karakter.',
	'email_long'      => 'Email terlalu panjang. Email tidak boleh melebihi {0, number} karakter.',
	'email_invalid'   => 'Email tidak sah.',
	'email_incorrect' => 'Email tidak benar.',
	'email_banned'    => 'Email ini terlarang.',
	'email_changed'   => 'Email berhasil diubah.',
	'email_taken'     => 'Email ({0}) sudah digunakan.',

	'newemail_match' => 'Email baru sama dengan email lama.',

	'logged_in'  => 'Anda berhasil masuk.',
	'logged_out' => 'Anda sudah keluar.',

	'system_error' => 'Ada kesalahan sistem. Silakan coba lagi.',

	'register_success'                         => 'Akun berhasil dibuat. Link aktivasi telah dikirimkan ke email.',
	'register_success_emailmessage_suppressed' => 'Akun berhasil dibuat.',

	'resetkey_invalid'   => 'Kode Reset tidak sah.',
	'resetkey_incorrect' => 'Kode Reset tidak benar.',
	'resetkey_expired'   => 'Kode Reset sudah kadaluarsa.',
	'password_reset'     => 'Password berhasil direset.',

	'activationkey_invalid'   => 'Kode Activasi tidak sah.',
	'activationkey_incorrect' => 'Kode Activasi tidak benar.',
	'activationkey_expired'   => 'Kode Activasi sudah kadaluarsa.',

	'reset_requested'                         => 'Link untuk reset Password telah dikirim ke email.',
	'reset_requested_emailmessage_suppressed' => 'Permintaan reset Password sudah dibuat.',
	'reset_exists'                            => 'Permintaan reset Password sudah ada. Silakan cek link reset di email.',

	'already_activated' => 'Akun sudah diaktifkan.',
	'activation_sent'   => 'Link Aktivasi sudah dikirim ke email.',
	'activation_exists' => 'Link Aktivasi sudah pernah dikirim ke email.',

	'email_activation_subject' => '{0} - Aktifkan Akun',
	'email_activation_body'    => "Halo,<br/><br/> untuk bisa masuk ke Akun, pertama Anda harus mengaktifkan akun Anda dengan cara klik link berikut ini: <strong><a href={0}{1}/{2}>{0}{1}/{2}</a></strong><br/><br/> Anda perlu menggunakan kode aktivasi berikut ini: <strong>{2}</strong><br/><br/> Jika Anda tidak melakukan pendaftaran di {0} akhir-akhir ini berarti ada kesalahan pengiriman terkait email ini, silakan diabaikan.",
	'email_activation_altbody' => 'Halo, ' . '\n\n' . 'untuk bisa masuk ke Akun, pertama Anda harus mengaktifkan akun Anda dengan cara klik link berikut ini:' . '\n{0}{1}/{2}\n\n' . 'Anda perlu menggunakan kode aktivasi berikut ini: {2}' . '\n\n' . 'Jika Anda tidak melakukan pendaftaran di {0} akhir-akhir ini berarti ada kesalahan pengiriman terkait email ini, silakan diabaikan.',

	'email_reset_subject' => '{0} - Permintaan Reset Password',
	'email_reset_body'    => "Halo,<br/><br/>untuk melakukan reset pada password Anda, silakan klik link berikut ini:<br/><br/><strong><a href={0}{1}/{2}>{0}{1}/{2}</a></strong><br/><br/>Anda perlu menggunakan kode reset berikut ini: <strong>{2}</strong><br/><br/>Jika Anda tidak meminta untuk mereset password pada {0}, maka telah terjadi kesalahan pengiriman email, silakan diabaikan.",
	'email_reset_altbody' => 'Halo, ' . '\n\n' . 'untuk melakukan reset pada password Anda, silakan klik link berikut ini:' . '\n{0}{1}/{2}\n\n' . 'Anda perlu menggunakan kode reset berikut ini: {2}' . '\n\n' . 'Jika Anda tidak meminta untuk mereset password pada {0}, maka telah terjadi kesalahan pengiriman email, silakan diabaikan.',

	'account_deleted'   => 'Akun berhasil dihapus.',
	'function_disabled' => 'Fungsi ini telah dinon-aktifkan.',

	'unknown_mail_type'         => 'Email tidak dikenal. Email tidak terkirim!',
	'activation_email_not_sent' => 'Link Aktivasi gagal dikirmkan ke email.',
	'reset_email_not_sent'      => 'Link untuk Reset Password gagal dikirim ke email.',

	'invalid_role'  => 'Anda tidak memiliki hak yang sah untuk mengakses halaman ini.',
	'invalid_group' => 'Anda tidak memiliki grup akses yang sah untuk mengakses halaman ini.',
];
