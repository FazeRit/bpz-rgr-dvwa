<?php

require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/secure_upload.inc.php';

if( isset( $_POST[ 'Upload' ] ) && isset( $_FILES[ 'uploaded' ] ) ) {
	list( $ok, $msg ) = dvwaSecureImageUpload( $_FILES[ 'uploaded' ], DVWA_WEB_PAGE_TO_ROOT . 'hackable/uploads/' );
	$html .= '<pre>' . htmlspecialchars( $msg, ENT_QUOTES, 'UTF-8' ) . '</pre>';
}

?>
