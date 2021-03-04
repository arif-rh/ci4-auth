<?php

return [
	'user_blocked'       => '現在アカウントがロックされています',
	'user_verify_failed' => 'キャプチャコードが無効です',

	'account_email_invalid'    => 'メールアドレスが間違っているか使用が禁止されています',
	'account_password_invalid' => 'パスワードが無効です',
	'account_not_found'        => 'アカウントが見つかりません',
	'account_inactive'         => 'アカウントが有効になっていません',
	'account_activated'        => 'アカウントが有効になりました',

	'login_remember_me_invalid' => 'リメンバーミーの欄が有効ではありません',

	'email_password_invalid'   => 'メールアドレス、パスワードが無効です',
	'email_password_incorrect' => 'パスワードが正しくありません',

	'remember_me_invalid' => 'リメンバーミーの欄が有効ではありません',

	'password_short'     => 'パスワードが短すぎます',
	'password_weak'      => 'パスワードが脆弱すぎます',
	'password_nomatch'   => 'パスワードが一致しません',
	'password_changed'   => 'パスワードが変更されました',
	'password_incorrect' => 'パスワードが正しくありません',
	'password_notvalid'  => 'パスワードが無効です',

	'newpassword_short'   => 'パスワードが短すぎます',
	'newpassword_long'    => 'パスワードが長すぎます',
	'newpassword_invalid' => 'パスワードには大文字、小文字、数字を使用してください',
	'newpassword_nomatch' => 'パスワードが一致しません',
	'newpassword_match'   => 'パスワードが古いパスワードと同じです',

	'email_short'     => 'メールアドレスが短すぎます。 {0, number} 文字必要',
	'email_long'      => 'メールアドレスが長すぎます。{0, number}文字を超えることはできません。',
	'email_invalid'   => 'メールアドレスが正しくありません',
	'email_incorrect' => 'メールアドレスが正しくありません',
	'email_banned'    => '使用できないメールアドレスです',
	'email_changed'   => 'メールアドレスが変更されました',
	'email_taken'     => 'メールアドレスが既に使用されています ({0}) ',

	'newemail_match' => 'メールアドレスが古いメールアドレスと同じです',

	'logged_in'  => 'ログイン中',
	'logged_out' => 'ログアウトしました',

	'system_error' => 'システムエラーです。再度お試しください。',

	'register_success'                         => 'アカウントが作成されました。メールを送信します。',
	'register_success_emailmessage_suppressed' => 'アカウントが作成されました',

	'resetkey_invalid'   => '無効なパスワードです',
	'resetkey_incorrect' => 'パスワードが正しくありません',
	'resetkey_expired'   => 'パスワードの期限が切れています',
	'password_reset'     => 'パスワードがリセットされました',

	'activationkey_invalid'   => '無効なパスワードです',
	'activationkey_incorrect' => 'パスワードが正しくありません',
	'activationkey_expired'   => 'パスワードの期限が切れています',

	'reset_requested'                         => 'パスワード再設定のメールを送信しました',
	'reset_requested_emailmessage_suppressed' => 'パスワード再設定のリクエストが送信されました',
	'reset_exists'                            => 'パスワード再設定のリクエストは既に存在します',

	'already_activated' => 'アカウントは既に有効です',
	'activation_sent'   => 'メールが送信されました',
	'activation_exists' => 'メールが既に送信されています',

	'email_activation_subject' => '{0} - アカウントを有効にする',
	'email_activation_body'    => "こんにちは<br/><br/> アカウントにログインできるようにするには、まず次のリンクをクリックしてアカウントをアクティブにする必要があります : <strong><a href={0}{1}/{2}>{0}{1}/{2}</a></strong><br/><br/> 続いて、次のアクティベーションキーを使用する必要があります: <strong>{2}</strong><br/><br/> サインアップしなかった場合 {0} このメッセージは誤って送信されました。無視してください。",
	'email_activation_altbody' => 'こんにちは ' . '\n\n' . 'アカウントにログインできるようにするには、まず次のリンクにアクセスしてアカウントをアクティブにする必要があります :' . '\n{0}{1}/{2}\n\n' . '続いて、次のアクティベーションキーを使用する必要があります: {2}' . '\n\n' . 'サインアップしなかった場合 {0} このメッセージは誤って送信されました。無視してください。',

	'email_reset_subject' => '{0} - パスワードリセット',
	'email_reset_body'    => "こんにちは<br/><br/>パスワードをリセットするには、次のリンクをクリックしてください :<br/><br/><strong><a href={0}{1}/{2}>{0}{1}/{2}</a></strong><br/><br/>次のパスワードリセットキーを使用する必要があります: <strong>{2}</strong><br/><br/>パスワードリセットキーをリクエストしなかった場合 {0} このメッセージは誤って送信されました。無視してください。",
	'email_reset_altbody' => 'こんにちは ' . '\n\n' . 'パスワードをリセットするには、次のリンクにアクセスしてください :' . '\n{0}{1}/{2}\n\n' . '続いて次のパスワードリセットキーを使用する必要があります: {2}' . '\n\n' . 'パスワードリセットキーをリクエストしなかった場合 {0} このメッセージは誤って送信されました。無視してください。',

	'account_deleted'   => 'アカウントが削除されました',
	'function_disabled' => 'この機能は無効になっています。',

	'unknown_mail_type' => '不明なメールタイプです。メールが送信されません',
	'activation_email_not_sent' => 'メールのアクティベーションを送信できませんでした。',
	'reset_email_not_sent' => 'パスワード再設定用のメールを送信できませんでした。',

	'invalid_role'  => 'このページにアクセスする権限がありません',
	'invalid_group' => 'このページにアクセスする権限がありません',
];
