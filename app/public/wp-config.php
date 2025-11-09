<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the web site, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * Localized language
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'local' );

/** Database username */
define( 'DB_USER', 'root' );

/** Database password */
define( 'DB_PASSWORD', 'root' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 *
 * Change these to different unique phrases! You can generate these using
 * the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}.
 *
 * You can change these at any point in time to invalidate all existing cookies.
 * This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',          'q1YoRRx:lNA1sEd8))kW((jdr(K^PXqw |P,OkB:lB/YpOU`=lr?y}^f!JfK9MbY' );
define( 'SECURE_AUTH_KEY',   '.%IJ0@AV64qm~PnplD*IVa0^.[h8p~dNm@$Vh}aWmBz1Uebgc+.k>h[_$FMfGdf5' );
define( 'LOGGED_IN_KEY',     'r~<Y] DI+11#7sVxG@3XZu(~^Z$KDB==&t:Gy?V/_ZN>BH-&*sOD=To~D]Qzv4Ua' );
define( 'NONCE_KEY',         'EnICi1U*[LvwZz~S>S1>BemR*U)/RC=nW Y:b;EC[6D#0{jbzC,D0l a6~hykh,Y' );
define( 'AUTH_SALT',         'A1zj(hC9~m:57xeX&$ UeB(<5l7o+S9R;J.4a47hrj%kjBKqQao`UvI588i%e*Kl' );
define( 'SECURE_AUTH_SALT',  'Ky-M]r32(Z2A{P;KP!Z:F `Cc}#W%/aPH0OY&tWz[F=%/P0*<<59NO@Al>WGxnnY' );
define( 'LOGGED_IN_SALT',    'l@*QA4VGkX{O)tZ|PO;}1Cq1O/X>6/ fy?]fj]^oc!`hwZT@`{0won3_Ffegz62F' );
define( 'NONCE_SALT',        'KN(^xIF~zvLQK-!Q7L51S}$E{y+,4@)}%2/k=~m:m8/h`}WB~Vf2kMh8(/]Rfm0:' );
define( 'WP_CACHE_KEY_SALT', 'yx4zLbB$o-><^E,S99l|&z^*%[ x%g,qc_M:]1Iofpe:$BLX33Gw_pw8oTp+l6@/' );


/**#@-*/

/**
 * WordPress database table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';


/* Add any custom values between this line and the "stop editing" line. */



/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
if ( ! defined( 'WP_DEBUG' ) ) {
	define( 'WP_DEBUG', false );
}

define( 'WP_ENVIRONMENT_TYPE', 'local' );
/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
