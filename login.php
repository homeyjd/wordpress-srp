<?php

require_once(dirname(__FILE__).'../../../wp-load.php');

// is the user logged in?
$user = wp_get_current_user();
$logged_in = ($user->ID !== 0);

if ($logged_in) {
	// create an additional session cookie for the additional SRP session
} else {
	// create a WordPress cookie based on the session key
}


if (empty(session_id())) {
	session_start();
}

if (!empty($_SESSION['srp_sess'])) {
	$srp = unserialize($_SESSION['srp_sess']);
} else {
	$srp = new SRP_WordPress_Session();
}

header('Content-Type: application/json');

try {
	if (!empty($_REQUEST['username'])) {
		$srp->username = substr($_REQUEST['username'], 0, 255);
		$s = $srp->user_salt();
		echo '{"s":"'.$s.'"}';
		
	} elseif (!empty($_REQUEST['A'])) {
		$B = $srp->B( substr($_REQUEST['A'], 0, 4096) );
		echo '{"B":"'.$B.'"}';
		
	} elseif (!empty($_REQUEST['M1'])) {
		$M2 = $srp->M2( substr($_REQUEST['M1'], 0, 4096) );
		echo '{"M2":"'.$M2.'"}';
		
	} else {
		throw new Exception("No valid input parameters");
	}
} catch (Exception $e) {
	echo '{"error":"'.$e.'"}';
}

exit();
