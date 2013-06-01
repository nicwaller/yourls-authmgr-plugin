<?php
/*
Plugin Name: Authorization Manager
Plugin URI:  https://github.com/nicwaller/yourls-authmgr-plugin
Description: Restrict classes of users to specific functions
Version:     0.9.2
Author:      nicwaller
Author URI:  https://github.com/nicwaller
*/

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

/****************** SET UP CONSTANTS ******************/

/**
 * This plugin uses filter chains to evaluate whether specific actions
 * should be allowed to proceed. The filter names are defined here.
 */
define( 'AUTHMGR_ALLOW',   'filter_authmgr_allow'   );
define( 'AUTHMGR_HASROLE', 'filter_authmgr_hasrole' );

// Define constants used for naming roles (but they don't work in config.php)
class AuthmgrRoles {
	const Administrator = 'Administrator';
	const Editor        = 'Editor';
	const Contributor   = 'Contributor';
}

// Define constants used for naming capabilities
class AuthmgrCapability {
	const ShowAdmin     = 'ShowAdmin'; // only display admin panel
	const AddURL        = 'AddURL';
	const DeleteURL     = 'DeleteURL';
	const EditURL       = 'EditURL';
	const ManagePlugins = 'ManagePlugins';
	const API           = 'API';
	const ViewStats     = 'ViewStats';
}	


/********** Add hooks to intercept functionality in CORE ********/

yourls_add_action( 'load_template_infos', 'authmgr_intercept_stats' );
function authmgr_intercept_stats() {
	authmgr_require_capability( AuthmgrCapability::ViewStats );
}

yourls_add_action( 'api', 'authmgr_intercept_api' );
function authmgr_intercept_api() {
	authmgr_require_capability( AuthmgrCapability::API );
}


yourls_add_action( 'auth_successful', 'authmgr_intercept_admin' );
/**
 * YOURLS processes most actions in the admin page. It would be ideal
 * to add a unique hook for each action, but unfortunately we need to
 * hook the admin page load itself, and try to figure out what action
 * is intended.
 *
 * At this point, reasonably assume that the current request is for
 * a rendering of the admin page.
 */
function authmgr_intercept_admin() {
	authmgr_require_capability( AuthmgrCapability::ShowAdmin );

        // we use this GET param to send up a feedback notice to user
        if ( isset( $_GET['access'] ) && $_GET['access']=='denied' ) {
                yourls_add_notice('Access Denied');
        }

        $action_capability_map = array(
      		'add' => AuthmgrCapability::AddURL,
        	'delete' => AuthmgrCapability::DeleteURL,
        	'edit_display' => AuthmgrCapability::EditURL,
        	'edit_save' => AuthmgrCapability::EditURL,
        	'activate' => AuthmgrCapability::ManagePlugins,
        	'deactivate' => AuthmgrCapability::ManagePlugins,
	);

	// intercept requests for plugin management
	if ( isset( $_REQUEST['plugin'] ) ) {
                $action_keyword = $_REQUEST['action'];
                $cap_needed = $action_capability_map[$action_keyword];
                if ( $cap_needed !== NULL && authmgr_have_capability( $cap_needed ) !== true) {
                        yourls_redirect( yourls_admin_url( '?access=denied' ), 302 );
                }
	}

	// Key actions like Add/Edit/Delete are AJAX requests
	if ( yourls_is_Ajax() ) {
		$action_keyword = $_REQUEST['action'];
		$cap_needed = $action_capability_map[$action_keyword];
		if ( authmgr_have_capability( $cap_needed ) !== true) {
			$err = array();
			$err['status'] = 'fail';
			$err['code'] = 'error:authorization';
			$err['message'] = 'Access Denied';
			$err['errorCode'] = '403';
			echo json_encode( $err );
			die();
		}
	}
}

yourls_add_filter( 'logout_link', 'authmgr_html_append_roles' );
/**
 * This is a cosmetic filter that makes it possible to see which roles are
 * currently available, just by mousing over the username in the logout link.
 */
function authmgr_html_append_roles( $original ) {
        $authenticated = yourls_is_valid_user();
        if ( $authenticated === true ) {
		$listcaps = implode(', ', authmgr_enumerate_current_capabilities());
		return '<div title="'.$listcaps.'">'.$original.'</div>';
	} else {
		return $original;
	}
}

/**************** CAPABILITY TEST/ENUMERATION ****************/

/*
 * If capability is not permitted in current context, then abort.
 * This is the most basic way to intercept unauthorized usage.
 */
function authmgr_require_capability( $capability ) {
	if ( !authmgr_have_capability( $capability ) ) {
		// If the user can't view admin interface, return a plain error.
		if ( !authmgr_have_capability( AuthmgrCapability::ShowAdmin ) ) {
			header("HTTP/1.0 403 Forbidden");
			die('Require permissions to show admin interface.');
		}
		// Otherwise, render errors in admin interface
                yourls_redirect( yourls_admin_url( '?access=denied' ), 302 );
		die();
	}
}

/*
 * Returns array of capabilities currently available.
 */
function authmgr_enumerate_current_capabilities() {
	$current_capabilities = array();
	$all_capabilities = authmgr_enumerate_all_capabilities();
	
	foreach ( $all_capabilities as $cap ) {
		if ( authmgr_have_capability( $cap ) ) {
			$current_capabilities[] = $cap;
		}
	}
	
	return $current_capabilities;
}

function authmgr_enumerate_all_capabilities() {
	return array(
		AuthmgrCapability::ShowAdmin,
		AuthmgrCapability::AddURL,
		AuthmgrCapability::DeleteURL,
		AuthmgrCapability::EditURL,
		AuthmgrCapability::ManagePlugins,
		AuthmgrCapability::API,
		AuthmgrCapability::ViewStats,
	);
}

/*
 * This is where everything comes together.
 * 
 * Use the "allow" filter chain to see if the requested capability
 * is permitted in the current context. Any function in the filter
 * chain can change the response, but well-behaved functions will
 * only change 'false' to 'true', never the other way around.
 */
function authmgr_have_capability( $capability ) {
        return yourls_apply_filter( AUTHMGR_ALLOW, false, $capability);
}

/******************* FILTERS THAT GRANT CAPABILITIES *****************************/
/* Whether an action is permitted is decided by running a filter chain. */
/*********************************************************************************/

/*
 * What capabilities are always available, including anonymous users?
 */
yourls_add_filter( AUTHMGR_ALLOW, 'authmgr_check_anon_capability', 5 );
function authmgr_check_anon_capability( $original, $capability ) {
	global $authmgr_anon_capabilities;

	// Shortcut - trust approval given by earlier filters
	if ( $original === true ) return true;

	// Make sure the anon rights list has been setup
	authmgr_environment_check();

	// Check list of capabilities that don't require authentication
	return in_array( $capability, $authmgr_anon_capabilities );
}

/*
 * What capabilities are available through role assignments to the active user?
 */
yourls_add_filter( AUTHMGR_ALLOW, 'authmgr_check_user_capability', 10 );
function authmgr_check_user_capability( $original, $capability ) {
	global $authmgr_role_capabilities;

	// Shortcut - trust approval given by earlier filters
	if ( $original === true ) return true;

	// ensure $authmgr_role_capabilities has been set up
	authmgr_environment_check();

	// If the user is not authenticated, then give up because only users have roles.
	$authenticated = yourls_is_valid_user();
	if ( $authenticated !== true )
		return false;

	// Enumerate the capabilities available to this user through roles
	$user_caps = array();
	
	foreach ( $authmgr_role_capabilities as $rolename => $rolecaps ) {
			if ( authmgr_user_has_role( YOURLS_USER, $rolename ) ) {
					$user_caps = array_merge( $user_caps, $rolecaps );
			}
	}
	$user_caps = array_unique( $user_caps );

	// Is the desired capability in the enumerated list of capabilities?
	return in_array( $capability, $user_caps );
}

/*
 * If the user is connecting from an IP address designated for admins,
 * then all capabilities are automatically granted.
 * 
 * By default, only 127.0.0.0/8 (localhost) is an admin range.
 */
yourls_add_filter( AUTHMGR_ALLOW, 'authmgr_check_admin_ipranges', 15 );
function authmgr_check_admin_ipranges( $original, $capability ) {
	global $authmgr_admin_ipranges;

        // Shortcut - trust approval given by earlier filters
        if ( $original === true ) return true;

        // ensure $authmgr_admin_ipranges is setup
        authmgr_environment_check();

	foreach ($authmgr_admin_ipranges as $range) {
		if ( authmgr_cidr_match( $_SERVER['REMOTE_ADDR'], $range ) )
			return true;
	}

	return $original; // effectively returns false
}

/*
 * What capabilities are available when making API requests without a username?
 */
yourls_add_filter( AUTHMGR_ALLOW, 'authmgr_check_apiuser_capability', 15 );
function authmgr_check_apiuser_capability( $original, $capability ) {
	// Shortcut - trust approval given by earlier filters
	if ( $original === true ) return true;

	// In API mode and not using user/path authn? Let it go.
	if ( yourls_is_API() && !isset($_REQUEST['username']) )
		return true;

	return $original;
}

/******************** ROLE TEST AND ENUMERATION ***********************/

/*
 * Determine whether a specific user has a role.
 */
function authmgr_user_has_role( $username, $rolename ) {
	return yourls_apply_filter( AUTHMGR_HASROLE, false, $username, $rolename );
}

// ******************* FILTERS THAT GRANT ROLE MEMBERSHIP *********************
// By filtering AUTHMGR_HASROLE, you can connect internal roles to something else.
// Any filter handlers should execute as quickly as possible.

/*
 * What role memberships are defined for the user in user/config.php?
 */
yourls_add_filter( AUTHMGR_HASROLE, 'authmgr_user_has_role_in_config');
function authmgr_user_has_role_in_config( $original, $username, $rolename ) {
	global $authmgr_role_assignment;

	// if no role assignments are created, grant everything
	// so the site still works even if stuff is configured wrong
	if ( empty( $authmgr_role_assignment ) )
		return true;

	// do this the case-insensitive way
	// the entire array was made lowercase in environment check
	$username = strtolower($username);
	$rolename = strtolower($rolename);

	// if the role doesn't exist, give up now.
	if ( !in_array( $rolename, array_keys( $authmgr_role_assignment ) ) )
		return false;

	$users_in_role = $authmgr_role_assignment[$rolename];
	return in_array( $username, $users_in_role );	
}


/********************* VALIDATE CONFIGURATION ************************/

function authmgr_environment_check() {
	global $authmgr_anon_capabilities;
	global $authmgr_role_capabilities;
	global $authmgr_role_assignment;

	if ( !isset( $authmgr_anon_capabilities) ) {
		$authmgr_anon_capabilities = array();
	}

	if ( !isset( $authmgr_role_capabilities) ) {
		$authmgr_role_capabilities = array(
			AuthmgrRoles::Administrator => array(
				AuthmgrCapability::ShowAdmin,
				AuthmgrCapability::AddURL,
				AuthmgrCapability::DeleteURL,
				AuthmgrCapability::EditURL,
				AuthmgrCapability::ManagePlugins,
				AuthmgrCapability::API,
                                AuthmgrCapability::ViewStats,
			),
			AuthmgrRoles::Editor => array(
				AuthmgrCapability::ShowAdmin,
				AuthmgrCapability::AddURL,
				AuthmgrCapability::EditURL,
				AuthmgrCapability::DeleteURL,
                                AuthmgrCapability::ViewStats,
			),
			AuthmgrRoles::Contributor => array(
				AuthmgrCapability::ShowAdmin,
				AuthmgrCapability::AddURL,
				AuthmgrCapability::ViewStats,
			),
		);
	}

	if ( !isset( $authmgr_role_assignment ) ) {
		$authmgr_role_assignment = array();
	}

	if ( !isset( $authmgr_iprange_roles ) ) {
		$authmgr_admin_ipranges = array(
			'127.0.0.0/8',
		);
	}

	// convert role assignment table to lower case if it hasn't been done already
	// this makes searches much easier!
	$authmgr_role_assignment_lower = array();
	foreach ( $authmgr_role_assignment as $key => $value ) {
		$t_key = strtolower( $key );
		$t_value = array_map('strtolower', $value);
		$authmgr_role_assignment_lower[$t_key] = $t_value;
	}
	$authmgr_role_assignment = $authmgr_role_assignment_lower;
	unset($authmgr_role_assignment_lower);

	return true;
}

// ***************** GENERAL UTILITY FUNCTIONS ********************

/*
 * Borrowed from:
 * http://stackoverflow.com/questions/594112/matching-an-ip-to-a-cidr-mask-in-php5
 */
function authmgr_cidr_match($ip, $range)
{
    list ($subnet, $bits) = split('/', $range);
    $ip = ip2long($ip);
    $subnet = ip2long($subnet);
    $mask = -1 << (32 - $bits);
    $subnet &= $mask; # nb: in case the supplied subnet wasn't correctly aligned
    return ($ip & $mask) == $subnet;
}
