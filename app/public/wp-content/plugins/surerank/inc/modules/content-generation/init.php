<?php
/**
 * Content Generation Init class
 *
 * Handles the initialization and hooks for or content generation functionality.
 *
 * @package SureRank\Inc\Modules\Content_Generation
 * @since 1.4.2
 */

namespace SureRank\Inc\Modules\Content_Generation;

use SureRank\Inc\Traits\Get_Instance;

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

/**
 * Init class
 *
 * Handles initialization and WordPress hooks for or content generation functionality.
 */
class Init {

	use Get_Instance;

	/**
	 * Constructor
	 */
	public function __construct() {
		Controller::get_instance();
		add_filter( 'surerank_api_controllers', [ $this, 'register_api_controller' ], 20 );
		add_filter( 'surerank_content_generation_inputs', [ $this, 'set_language' ] );
	}

	/**
	 * Register API controller for this module.
	 *
	 * @param array<string> $controllers Existing controllers.
	 * @return array<string> Updated controllers.
	 * @since 1.4.2
	 */
	public function register_api_controller( $controllers ) {
		$controllers[] = '\SureRank\Inc\Modules\Content_Generation\Api';
		return $controllers;
	}

	/**
	 * Set language in content generation inputs.
	 *
	 * @param array<string> $inputs Existing inputs.
	 * @return array<string> Updated inputs.
	 * @since 1.4.3
	 */
	public function set_language( $inputs ) {
		$language = get_bloginfo( 'language' );
		if ( 'en-US' !== $language ) {
			$inputs['language'] = $language;
		}
		return $inputs;
	}
}
