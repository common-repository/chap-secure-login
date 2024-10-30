<?php
/*
Plugin Name: Chap Secure Password Login
Plugin URI: https://www.mrred.it/chap-secure-login-a-wordpress-plugin-for-secure-password-authentication/
Description: Do not show password, during login, on an insecure channel (without SSL) (SHA-256 encryption).
Version: 1.6.6
Author: Enrico Rossomando (redsend)
Author URI: https://www.mrred.it
*/

/*  Copyright 2007-2020  Enrico Rossomando (email : redsend@gmail.com)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

if ( ! defined( 'ABSPATH' ) ) {
        exit; // Exit if accessed directly
}

function chap_plugin_loaded(){

	if(!session_id())
		session_start();
	
	if (!isset($_SESSION['dochap']))
		$_SESSION['dochap'] = 1;
	
	if (defined("XMLRPC_REQUEST") && XMLRPC_REQUEST == true)
		$_SESSION['dochap'] = 0;
		
	if (!isset($_SESSION['challenge']))
		$_SESSION['challenge']=md5(rand(1,100000));
	
	session_write_close();

}

add_action('plugins_loaded', 'chap_plugin_loaded');


function generate_javascript(){
	
	if(!session_id())
		session_start();
	
	if (isset($_SESSION['dochap']) && $_SESSION['dochap'] == 1){
	
	?>
	
	<script language="javascript" type="text/javascript" src="<?php echo plugins_url( 'js/sha256.js', __FILE__ ); ?>" ></script>
	<script language="javascript" type="text/javascript" src="<?php echo plugins_url( 'js/md5.js', __FILE__ ); ?>" ></script>
	<script language="javascript" type="text/javascript">
		function doCHAP (){
		
			var userid = document.getElementById('user_login');
			var psw = document.getElementById('user_pass');
			
			if (!userid.value || !psw.value)
				return false;
			
			var password = psw.value;
			
			var shaObj = new jsSHA(hex_md5(password)+'<?php echo $_SESSION['challenge']?>',"ASCII");
			psw.value = shaObj.getHash("SHA-256", "HEX");
			
			return true;
		
		}
	</script>
	
	<?php
	
	session_destroy();
	}
}

add_action('login_head', 'generate_javascript');



function integrate_CHAP_login_form(){

	if(!session_id())
		session_start();
	
	if (isset($_SESSION['dochap']) && $_SESSION['dochap'] == 1){

	?>
	
	<a style="border-width:0px;text-decoration:none;" href="http://www.mrred.it/chap-secure-login-a-wordpress-plugin-for-secure-password-authentication/" title="More info on Chap Secure Login Plugin for secure password authentication">
		<img style="border-width:0px;text-decoration:none;height:15px;width:15px;position:relative;float:left;margin-top:-75px;margin-left:70px;" alt="> Encryption password!" src="<?php echo plugins_url( 'lock.png', __FILE__ ); ?>">
	</a>
	
	<script language="javascript" type="text/javascript">
		var form_login = document.getElementById('loginform');
		form_login.onsubmit = function (){ return doCHAP();};
	</script>
	
	<?php
	
	} else {
	
	?>
	
	<script language="javascript" type="text/javascript">
		alert("CAUTION!!! Password is sent unencrypted.");
	</script>
	
	<?php
	
	session_destroy();
	}

}

add_action('login_form', 'integrate_CHAP_login_form');


if ( ! function_exists('wp_check_password') ):
/**
 * wp_check_password() - Checks the plaintext password against the encrypted Password
 *
 * Maintains compatibility between old version and the new cookie
 * authentication protocol using PHPass library. The $hash parameter
 * is the encrypted password and the function compares the plain text
 * password when encypted similarly against the already encrypted
 * password to see if they match.
 *
 * For integration with other applications, this function can be
 * overwritten to instead use the other package password checking
 * algorithm.
 *
 * @since 2.5
 * @global object $wp_hasher PHPass object used for checking the password
 *	against the $hash + $password
 * @uses PasswordHash::CheckPassword
 *
 * @param string $password Plaintext user's password
 * @param string $hash Hash of the user's password to check against.
 * @return bool False, if the $password does not match the hashed password
 */
function wp_check_password($password, $hash, $user_id = '') {
	
	if(!session_id())
		session_start();
	
	// If the hash was updated to the new hash before this plugin
	// was installed, rehash as md5.
	if ( strlen($hash) > 32 ) {
	
		if ($_SESSION['dochap'] == 1) {
			$_SESSION['dochap'] = 0;
			session_write_close();
			return false;
		}
		
		global $wp_hasher;
		if ( empty($wp_hasher) ) {
			require_once( ABSPATH . 'wp-includes/class-phpass.php');
			$wp_hasher = new PasswordHash(8, TRUE);
		}
		$check = $wp_hasher->CheckPassword($password, $hash);
		if ( $check && $user_id ) {
			// Rehash using new hash.
			wp_set_password($password, $user_id);
			$user = get_userdata($user_id);
			$hash = $user->user_pass;
		}

		$_SESSION['dochap'] = 1;

		session_write_close();
		return apply_filters('check_password', $check, $password, $hash, $user_id);
	}

	if ($_SESSION['dochap'] == 1)
		$check = ( hash("sha256", $hash.$_SESSION['challenge']) == $password );
	else
		$check = ( $hash == md5($password) );

	session_destroy();
	return apply_filters('check_password', $check, $password, $hash, $user_id);
}
endif;


if ( !function_exists('wp_hash_password') ):
/**
 * wp_hash_password() - Create a hash (encrypt) of a plain text password
 *
 * @param string $password Plain text user password to hash
 * @return string The hash string of the password
 */
function wp_hash_password($password) {
	return md5($password);
}
endif;


function destroy_CHAP_challenge(){
	if(!session_id())
		session_start();
	unset($_SESSION['challenge']);
	session_write_close();
}

add_action('wp_logout', 'destroy_CHAP_challenge');
