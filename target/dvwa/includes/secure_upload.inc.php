<?php
function dvwaSecureImageUpload( $file, $target_dir ) {
	$allowed = array( IMAGETYPE_JPEG => 'jpg', IMAGETYPE_PNG => 'png' );

	if( !isset( $file[ 'error' ] ) || $file[ 'error' ] !== UPLOAD_ERR_OK ) {
		return array( false, 'Your image was not uploaded.' );
	}
	if( $file[ 'size' ] <= 0 || $file[ 'size' ] >= 100000 ) {
		return array( false, 'Your image was not uploaded. We can only accept JPEG or PNG images.' );
	}
	$info = @getimagesize( $file[ 'tmp_name' ] );
	if( $info === false || !isset( $allowed[ $info[ 2 ] ] ) ) {
		return array( false, 'Your image was not uploaded. We can only accept JPEG or PNG images.' );
	}
	$img = ( $info[ 2 ] === IMAGETYPE_JPEG ) ? @imagecreatefromjpeg( $file[ 'tmp_name' ] ) : @imagecreatefrompng( $file[ 'tmp_name' ] );
	if( $img === false ) {
		return array( false, 'Your image was not uploaded. We can only accept JPEG or PNG images.' );
	}
	$name = bin2hex( random_bytes( 16 ) ) . '.' . $allowed[ $info[ 2 ] ];
	$dest = rtrim( $target_dir, '/' ) . '/' . $name;
	$ok   = ( $info[ 2 ] === IMAGETYPE_JPEG ) ? imagejpeg( $img, $dest, 90 ) : imagepng( $img, $dest, 9 );
	imagedestroy( $img );
	if( !$ok ) {
		return array( false, 'Your image was not uploaded.' );
	}
	return array( true, $name . ' succesfully uploaded!' );
}
?>
