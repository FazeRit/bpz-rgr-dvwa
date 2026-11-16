<?php

$allowedPages = array( 'include.php', 'file1.php', 'file2.php', 'file3.php' );

$file = isset( $_GET[ 'page' ] ) ? $_GET[ 'page' ] : null;

if( $file !== null && !in_array( $file, $allowedPages, true ) ) {
	http_response_code( 404 );
	echo "ERROR: File not found!";
	exit;
}

?>
